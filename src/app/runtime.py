import queue
import re
import sqlite3
import socket
import threading
import time
import os
import ipaddress
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

try:
    import psutil
except Exception:  # pragma: no cover - optional runtime dependency
    psutil = None

from src.app.packet_queries import (
    query_offline_frames_page as packet_query_offline_frames_page,
    query_packets_filtered as packet_query_packets_filtered,
    query_packets_page as packet_query_packets_page,
)
from src.app.offline_imports import import_offline_pcap as run_offline_import
from src.subprocess_utils import run_command_capture
from src.config import CONFIG
from src.core.aggregation.session_aggregator import SessionAggregator
from src.core.audit.service import AuditService
from src.core.capture.capture_engine import CaptureEngine
from src.core.common import parse_ts_float, rank_to_level, render_ts_text
from src.core.ctf import FlowWorkbenchService, PacketBatchExportService
from src.core.detection.model_engine import ModelEngine
from src.core.detection.rule_engine import RuleEngine
from src.core.detection.service import DetectionService
from src.core.detection.attack_knowledge import get_attack_knowledge
from src.core.notify.service import NotificationService
from src.core.offline import OfflineParserConfig, OfflineParserError
from src.core.offline.adapter import LegacyPacketBatchView, iter_offline_generic_frames
from src.core.report.service import ReportService
from src.core.storage.db import Database, now_text
from src.core.storage.offline_packet_store import OfflinePacketStore
from src.core.whitelist_blacklist.service import ListService


@dataclass(frozen=True)
class OfflineImportProfile:
    mode: str
    batch_size: int
    raw_hex_preview_bytes: int
    store_raw_hex: bool
    store_packets: bool
    enable_app_meta: bool
    enable_detection: bool
    parser_threads: int
    cpu_limit_percent: int
    detection_flush_interval_batches: int


@dataclass(frozen=True)
class AppRuntimeDeps:
    db: Database | None = None
    audit: AuditService | None = None
    list_service: ListService | None = None
    model_engine: ModelEngine | None = None
    rule_engine: RuleEngine | None = None
    detector: DetectionService | None = None
    notifier: NotificationService | None = None
    report_service: ReportService | None = None
    flow_workbench: FlowWorkbenchService | None = None
    packet_batch_export: PacketBatchExportService | None = None
    offline_packet_store: OfflinePacketStore | None = None
    capture: CaptureEngine | None = None
    aggregator: SessionAggregator | None = None


class AppRuntime:
    def __init__(self, deps: AppRuntimeDeps | None = None) -> None:
        resolved = deps or AppRuntimeDeps()
        self.db = resolved.db or Database()
        self.audit = resolved.audit or AuditService(self.db)
        self.list_service = resolved.list_service or ListService(self.db)
        self.model_engine = resolved.model_engine or ModelEngine(CONFIG.model_path)
        self.rule_engine = resolved.rule_engine or RuleEngine()
        self.detector = resolved.detector or DetectionService(self.db, self.list_service, self.model_engine, self.rule_engine)
        self.notifier = resolved.notifier or NotificationService()
        self.flow_workbench = resolved.flow_workbench or FlowWorkbenchService()
        self.packet_batch_export = resolved.packet_batch_export or PacketBatchExportService()
        self.offline_packet_store: OfflinePacketStore | None = resolved.offline_packet_store
        self.offline_packet_store_error = ""
        if self.offline_packet_store is None and bool(getattr(CONFIG, "offline_use_duckdb", True)):
            try:
                self.offline_packet_store = OfflinePacketStore(Path(getattr(CONFIG, "offline_duckdb_path", Path("data/offline_packets.duckdb"))))
            except Exception as exc:
                self.offline_packet_store = None
                self.offline_packet_store_error = f"{type(exc).__name__}: {exc}"
        self.report_service = resolved.report_service or ReportService(self.db, offline_packet_store=self.offline_packet_store)
        self.packet_queue: queue.Queue = queue.Queue(maxsize=10000)
        self.capture = resolved.capture or CaptureEngine(self.packet_queue)
        self.aggregator = resolved.aggregator or SessionAggregator()
        self.blocked_ips: set[str] = set()
        self.running = False
        self.worker: threading.Thread | None = None
        self.last_summary = {
            "total_packets": 0,
            "alerts": 0,
            "active_sessions": 0,
            "uptime_sec": 0,
            "proto_distribution": {},
            "top_abnormal_ips": [],
            "privacy_blocks": 0,
            "firewall_blocks": 0,
        }
        self.start_ts = time.time()
        self.raw_hex_preview_bytes = 512
        self.offline_progress = {
            "running": False,
            "processed": 0,
            "alerts": 0,
            "file": "",
            "percent": 0.0,
            "bytes": 0,
            "total_bytes": 0,
            "mode": self._normalize_offline_mode(getattr(CONFIG, "offline_mode_default", "balanced")),
        }
        self._offline_cpu_last_sample = 0.0
        self._offline_write_transaction_open = False
        self._offline_write_commit_interval_batches = 1
        self._offline_write_batches_since_commit = 0
        self._offline_indexes_suspended = False
        self._offline_sqlite_write_enabled = True
        self._offline_feature_buffer: list[dict] = []
        self._offline_feature_flush_size = 8000
        self._offline_detection_batch_counter = 0
        self._traffic_stat_interval_seconds = 5.0
        self._log_cleanup_interval_seconds = 300.0
        self._last_traffic_stat_flush_ts = 0.0
        self._last_log_cleanup_ts = 0.0
        self._packet_query_chunk_size = 1000
        self._bootstrap_firewall_blacklist_sync()

    @staticmethod
    def _normalize_offline_mode(mode: str) -> str:
        text = str(mode or "").strip().lower()
        if text in {"extreme", "speed", "fast", "turbo"}:
            return "extreme"
        return "balanced"

    @staticmethod
    def _logical_cpu_count() -> int:
        return max(1, int(os.cpu_count() or 1))

    @staticmethod
    def _to_int(value: object, default: int) -> int:
        try:
            return int(value)
        except Exception:
            return int(default)

    def get_offline_import_profile(self, mode: str = "") -> OfflineImportProfile:
        selected = self._normalize_offline_mode(mode or getattr(CONFIG, "offline_mode_default", "balanced"))
        logical_cores = self._logical_cpu_count()
        if selected == "extreme":
            return OfflineImportProfile(
                mode="extreme",
                batch_size=max(1000, self._to_int(getattr(CONFIG, "offline_extreme_batch_size", 7000), 7000)),
                raw_hex_preview_bytes=max(0, self._to_int(getattr(CONFIG, "offline_extreme_raw_hex_preview_bytes", 256), 256)),
                store_raw_hex=bool(getattr(CONFIG, "offline_extreme_store_raw_hex", True)),
                store_packets=bool(getattr(CONFIG, "offline_extreme_store_packets", True)),
                enable_app_meta=bool(getattr(CONFIG, "offline_extreme_enable_app_meta", True)),
                enable_detection=bool(getattr(CONFIG, "offline_extreme_enable_detection", True)),
                parser_threads=max(1, logical_cores),
                cpu_limit_percent=max(0, self._to_int(getattr(CONFIG, "offline_extreme_cpu_limit_percent", 0), 0)),
                detection_flush_interval_batches=max(1, self._to_int(getattr(CONFIG, "offline_extreme_detection_flush_interval_batches", 8), 8)),
            )
        return OfflineImportProfile(
            mode="balanced",
            batch_size=max(1000, self._to_int(getattr(CONFIG, "offline_balanced_batch_size", 4000), 4000)),
            raw_hex_preview_bytes=max(0, self._to_int(getattr(CONFIG, "offline_balanced_raw_hex_preview_bytes", 256), 256)),
            store_raw_hex=bool(getattr(CONFIG, "offline_balanced_store_raw_hex", True)),
            store_packets=bool(getattr(CONFIG, "offline_balanced_store_packets", True)),
            enable_app_meta=bool(getattr(CONFIG, "offline_balanced_enable_app_meta", True)),
            enable_detection=bool(getattr(CONFIG, "offline_balanced_enable_detection", True)),
            parser_threads=max(1, logical_cores // 2),
            cpu_limit_percent=max(0, self._to_int(getattr(CONFIG, "offline_balanced_cpu_limit_percent", 70), 70)),
            detection_flush_interval_batches=max(1, self._to_int(getattr(CONFIG, "offline_balanced_detection_flush_interval_batches", 2), 2)),
        )

    def is_capture_running(self) -> bool:
        return bool(self.running and getattr(self.capture, "running", False))

    def _offline_store_enabled(self) -> bool:
        return self.offline_packet_store is not None

    def start_learning(self, mode: str = "fast") -> None:
        seconds = CONFIG.baseline_fast_seconds if mode == "fast" else CONFIG.baseline_standard_seconds
        self.detector.start_learning(seconds)

    def start_capture(self, interface: str, capture_outbound: bool) -> None:
        self.capture.start(interface, capture_outbound)
        if not self.running:
            self.running = True
            self._last_traffic_stat_flush_ts = time.time()
            self._last_log_cleanup_ts = time.time()
            self.worker = threading.Thread(target=self._worker_loop, daemon=True)
            self.worker.start()

    def stop_capture(self) -> None:
        self.capture.stop()
        self._flush_realtime_traffic_stat(force=True)
        self.running = False
        worker = self.worker
        self.worker = None
        if worker and worker.is_alive() and worker is not threading.current_thread():
            worker.join(timeout=max(1.0, CONFIG.capture_batch_timeout * 4))
        # 停止环境预识别（学习模式）
        self.detector.learning_until = 0

    def close(self) -> None:
        self.stop_capture()
        self.list_service.close()
        if self.offline_packet_store is not None:
            self.offline_packet_store.close()
        self.db.close()

    def set_interface_enabled(self, interface: str, enabled: bool) -> tuple[bool, str]:
        return self.capture.set_interface_enabled(interface, enabled)

    def _worker_loop(self) -> None:
        while self.running:
            batch: list[dict] = []
            try:
                for _ in range(CONFIG.capture_batch_size):
                    batch.append(self.packet_queue.get(timeout=CONFIG.capture_batch_timeout))
            except queue.Empty:
                pass
            if not batch:
                continue
            self._store_captured_packets(batch, source="live")
            self.aggregator.ingest_batch(batch)
            now_ts = time.time()
            self.aggregator.cleanup_expired(now_ts, CONFIG.session_timeout_seconds)
            features = self.aggregator.flush_features(now_ts)
            alerts = self.detector.process(features, source="live")
            self._update_summary(batch, alerts)
            self._notify_high_risk_alerts(alerts)
            self._run_realtime_maintenance(now_ts)

    def _update_summary(self, batch: list[dict], alerts: list[dict]) -> None:
        self.last_summary["total_packets"] += len(batch)
        self.last_summary["alerts"] += len(alerts)
        self.last_summary["active_sessions"] = len(self.aggregator.sessions)
        self.last_summary["uptime_sec"] = int(time.time() - self.start_ts)
        self.last_summary["privacy_blocks"] += sum(1 for a in alerts if a.get("sub_category") == "隐私追踪拦截")
        self.last_summary["firewall_blocks"] = len(self.blocked_ips)
        proto_counter = Counter(p["proto"] for p in batch)
        for k, v in proto_counter.items():
            self.last_summary["proto_distribution"][k] = self.last_summary["proto_distribution"].get(k, 0) + v
        ip_counter = Counter(a["src_ip"] for a in alerts)
        self.last_summary["top_abnormal_ips"] = ip_counter.most_common(10)

    def reset_realtime_summary(self) -> None:
        self.start_ts = time.time()
        self.last_summary = {
            "total_packets": 0,
            "alerts": 0,
            "active_sessions": 0,
            "uptime_sec": 0,
            "proto_distribution": {},
            "top_abnormal_ips": [],
            "privacy_blocks": 0,
            "firewall_blocks": len(self.blocked_ips),
        }

    def _run_realtime_maintenance(self, now_ts: float) -> None:
        self._flush_realtime_traffic_stat(now_ts=now_ts)
        self._cleanup_old_logs_if_due(now_ts=now_ts)

    def _flush_realtime_traffic_stat(self, now_ts: float | None = None, force: bool = False) -> None:
        ts_now = float(now_ts or time.time())
        if not force and ts_now - self._last_traffic_stat_flush_ts < self._traffic_stat_interval_seconds:
            return
        if int(self.last_summary.get("total_packets", 0) or 0) <= 0:
            self._last_traffic_stat_flush_ts = ts_now
            return
        c = self.db.conn.cursor()
        c.execute(
            "INSERT INTO traffic_stats(ts, inbound_packets, outbound_packets, active_sessions) VALUES(?,?,?,?)",
            (now_text(), self.last_summary["total_packets"], 0, self.last_summary["active_sessions"]),
        )
        self.db.conn.commit()
        self._last_traffic_stat_flush_ts = ts_now

    def _cleanup_old_logs_if_due(self, now_ts: float | None = None) -> None:
        ts_now = float(now_ts or time.time())
        if ts_now - self._last_log_cleanup_ts < self._log_cleanup_interval_seconds:
            return
        self.db.cleanup_old_logs()
        self._last_log_cleanup_ts = ts_now

    def _notify_high_risk_alerts(self, alerts: list[dict]) -> None:
        for alert in alerts:
            self.notifier.notify_high_risk(alert)

    def _store_captured_packets(
        self,
        packets: Sequence[Mapping[str, object]],
        source: str,
        preview_bytes_override: int | None = None,
        store_raw_hex_override: bool | None = None,
        commit: bool = True,
    ) -> None:
        if not packets:
            return
        c = self.db.conn.cursor()
        preview_bytes = self.raw_hex_preview_bytes
        if preview_bytes_override is not None:
            preview_bytes = max(0, int(preview_bytes_override))
        store_raw_hex = True
        if store_raw_hex_override is not None:
            store_raw_hex = bool(store_raw_hex_override)
        def _format_ts(packet_ts: object) -> float:
            try:
                ts_f = float(packet_ts or 0.0)
            except Exception:
                ts_f = time.time()
            return float(ts_f)
        rows = [
            (
                _format_ts(p.get("ts", time.time())),
                p.get("src_ip", ""),
                p.get("dst_ip", ""),
                int(p.get("src_port", 0)),
                int(p.get("dst_port", 0)),
                p.get("proto", "OTHER"),
                int(p.get("length", 0)),
                p.get("direction", "inbound"),
                int(p.get("process_id", 0)),
                p.get("process_name", ""),
                (str(p.get("raw_hex", ""))[: preview_bytes * 2] if store_raw_hex else ""),
                source,
            )
            for p in packets
        ]
        if source == "offline" and self._offline_store_enabled():
            assert self.offline_packet_store is not None
            self.offline_packet_store.insert_rows(rows)
            return
        c.executemany(
            """
            INSERT INTO captured_packets(ts, src_ip, dst_ip, src_port, dst_port, proto, length, direction, process_id, process_name, raw_hex, source)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            rows,
        )
        if commit:
            self.db.conn.commit()

    def _begin_offline_write_mode(self, profile: OfflineImportProfile) -> None:
        # 导入阶段采用分段大事务，显著降低每批commit开销。
        self._offline_sqlite_write_enabled = bool(
            profile.enable_detection or (profile.store_packets and not self._offline_store_enabled())
        )
        conn = self.db.conn
        c = conn.cursor()
        if self._offline_sqlite_write_enabled:
            c.execute("PRAGMA busy_timeout=5000;")
            try:
                c.execute("PRAGMA temp_store=MEMORY;")
                c.execute("PRAGMA mmap_size=268435456;")
                c.execute("PRAGMA cache_size=-120000;")
                c.execute("PRAGMA journal_mode=MEMORY;")
                if profile.mode == "extreme":
                    c.execute("PRAGMA synchronous=OFF;")
                else:
                    c.execute("PRAGMA synchronous=NORMAL;")
            except sqlite3.OperationalError:
                # 若数据库被其他窗口占用，降级使用默认PRAGMA以保证可用性。
                pass
        interval = (
            int(getattr(CONFIG, "offline_extreme_commit_interval_batches", 64))
            if profile.mode == "extreme"
            else int(getattr(CONFIG, "offline_balanced_commit_interval_batches", 16))
        )
        self._offline_feature_buffer.clear()
        self._offline_feature_flush_size = 16000 if profile.mode == "extreme" else 8000
        self._offline_detection_batch_counter = 0
        self._offline_write_commit_interval_batches = max(1, interval)
        self._offline_write_batches_since_commit = 0
        if self._offline_store_enabled():
            assert self.offline_packet_store is not None
            self.offline_packet_store.begin_bulk()
        if self._offline_sqlite_write_enabled:
            self.db.suspend_offline_import_indexes()
            self._offline_indexes_suspended = True
            try:
                conn.execute("BEGIN IMMEDIATE")
                self._offline_write_transaction_open = True
            except sqlite3.OperationalError:
                self._offline_write_transaction_open = False
        else:
            self._offline_indexes_suspended = False
            self._offline_write_transaction_open = False

    def _flush_offline_write_if_needed(self, force: bool = False) -> None:
        if not self._offline_write_transaction_open:
            return
        self._offline_write_batches_since_commit += 1
        if not force and self._offline_write_batches_since_commit < self._offline_write_commit_interval_batches:
            return
        self.db.conn.commit()
        self._offline_write_batches_since_commit = 0
        if not force:
            self.db.conn.execute("BEGIN IMMEDIATE")

    def _end_offline_write_mode(self) -> None:
        try:
            if self._offline_write_transaction_open:
                self._flush_offline_write_if_needed(force=True)
        finally:
            self._offline_write_transaction_open = False
            self._offline_feature_buffer.clear()
            self._offline_detection_batch_counter = 0
            if self._offline_indexes_suspended:
                lightweight = bool(getattr(CONFIG, "offline_defer_secondary_indexes", True))
                self.db.resume_offline_import_indexes(lightweight=lightweight)
                self._offline_indexes_suspended = False
            if self._offline_store_enabled():
                assert self.offline_packet_store is not None
                self.offline_packet_store.end_bulk()
            if self._offline_sqlite_write_enabled:
                c = self.db.conn.cursor()
                try:
                    c.execute("PRAGMA journal_mode=WAL;")
                    c.execute("PRAGMA synchronous=NORMAL;")
                except sqlite3.OperationalError:
                    pass
            self._offline_sqlite_write_enabled = True

    def query_alerts(
        self,
        limit: int = 200,
        level: str = "",
        ip: str = "",
        category: str = "",
        process_name: str = "",
        source: str = "",
    ) -> list[dict]:
        c = self.db.conn.cursor()
        sql = "SELECT * FROM alerts WHERE 1=1"
        args: list = []
        if level:
            sql += " AND level=?"
            args.append(level)
        if category:
            sql += " AND category=?"
            args.append(category)
        if ip:
            sql += " AND (src_ip LIKE ? OR dst_ip LIKE ?)"
            args.extend([f"%{ip}%", f"%{ip}%"])
        if process_name:
            sql += " AND process_name LIKE ?"
            args.append(f"%{process_name}%")
        if source:
            sql += " AND source=?"
            args.append(source)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        c.execute(sql, tuple(args))
        rows = [dict(r) for r in c.fetchall()]
        for row in rows:
            if row.get("attack_desc") and row.get("mitigation") and row.get("attack_type"):
                continue
            knowledge = get_attack_knowledge(str(row.get("sub_category", "")))
            row["attack_type"] = row.get("attack_type") or knowledge.get("type", "")
            row["attack_desc"] = row.get("attack_desc") or knowledge.get("description", "")
            row["mitigation"] = row.get("mitigation") or knowledge.get("mitigation", "")
        return rows

    @staticmethod
    def _build_packet_rule_sql(expression: str) -> tuple[str, list]:
        expr = str(expression or "").strip()
        if not expr or "||" in expr or "!" in expr:
            return "", []
        parts = [p.strip() for p in expr.split("&&") if p.strip()]
        if not parts:
            return "", []
        clauses: list[str] = []
        args: list = []
        text_fields = {"process": "process_name", "process_name": "process_name", "proto": "proto", "source": "source"}
        scalar_fields = {
            "ip.src": "src_ip",
            "src_ip": "src_ip",
            "ip.dst": "dst_ip",
            "dst_ip": "dst_ip",
            "tcp.srcport": "src_port",
            "udp.srcport": "src_port",
            "src_port": "src_port",
            "tcp.dstport": "dst_port",
            "udp.dstport": "dst_port",
            "dst_port": "dst_port",
            "frame.len": "length",
            "len": "length",
            "length": "length",
            "frame.number": "id",
            "id": "id",
            "process": "process_name",
            "process_name": "process_name",
            "proto": "proto",
            "source": "source",
        }
        pair_fields = {
            "ip.addr": ("src_ip", "dst_ip"),
            "ip": ("src_ip", "dst_ip"),
            "port": ("src_port", "dst_port"),
            "tcp.port": ("src_port", "dst_port"),
            "udp.port": ("src_port", "dst_port"),
        }
        numeric_fields = {"port", "tcp.port", "udp.port", "tcp.srcport", "udp.srcport", "src_port", "tcp.dstport", "udp.dstport", "dst_port", "frame.len", "len", "length", "frame.number", "id"}

        def coerce_value(field: str, raw: str):
            if field not in numeric_fields:
                return raw.upper() if field == "proto" else raw
            try:
                return int(float(raw))
            except Exception:
                return None

        for term in parts:
            low = term.lower()
            if low in {"tcp", "udp", "icmp"}:
                clauses.append("proto = ?")
                args.append(low.upper())
                continue
            m_contains = re.match(r"^([a-zA-Z0-9_.]+)\s+contains\s+(.+)$", term.strip(), flags=re.IGNORECASE)
            if m_contains:
                field = str(m_contains.group(1) or "").strip().lower()
                value = str(m_contains.group(2) or "").strip().strip("'").strip('"')
                if not value:
                    continue
                if field in {"ip", "ip.addr"}:
                    clauses.append("(src_ip LIKE ? OR dst_ip LIKE ?)")
                    args.extend([f"%{value}%", f"%{value}%"])
                elif field in text_fields:
                    clauses.append(f"{text_fields[field]} LIKE ?")
                    args.append(f"%{value}%")
                else:
                    return "", []
                continue
            m = re.match(r"^([a-zA-Z0-9_.]+)\s*(==|!=|>=|<=|>|<)\s*(.+)$", term.strip())
            if not m:
                return "", []
            field = str(m.group(1) or "").strip().lower()
            op = str(m.group(2) or "").strip()
            value_raw = str(m.group(3) or "").strip().strip("'").strip('"')
            op_sql = "=" if op == "==" else op
            value = coerce_value(field, value_raw)
            if value is None:
                return "", []
            if field in pair_fields:
                left, right = pair_fields[field]
                clauses.append(f"({left} {op_sql} ? OR {right} {op_sql} ?)")
                args.extend([value, value])
            elif field in scalar_fields:
                clauses.append(f"{scalar_fields[field]} {op_sql} ?")
                args.append(value)
            else:
                return "", []
        if not clauses:
            return "", []
        return " AND " + " AND ".join(f"({c})" for c in clauses), args

    @staticmethod
    def _packet_sort_value(row: dict, key: str):
        normalized = str(key or "").strip().lower()
        if normalized in {"id", "src_port", "dst_port", "length"}:
            return int(row.get(normalized, 0) or 0)
        if normalized == "risk_level":
            return {"high": 3, "medium": 2, "low": 1}.get(str(row.get("risk_level", "normal")).lower(), 0)
        if normalized == "ts":
            return float(row.get("ts_epoch", 0.0) or 0.0)
        return str(row.get(normalized, "") or "").lower()

    @staticmethod
    def _normalize_packet_sort_key(sort_key: str) -> str:
        key = str(sort_key or "").strip().lower()
        if key in {"", "no", "delta"}:
            return "ts"
        allowed = {"ts", "id", "risk_level", "process_name", "src_ip", "dst_ip", "src_port", "dst_port", "proto", "length", "source"}
        return key if key in allowed else "ts"

    def _build_packet_sort_sql(self, sort_key: str, sort_desc: bool) -> str:
        key = self._normalize_packet_sort_key(sort_key)
        direction = "DESC" if sort_desc else "ASC"
        field_map = {
            "ts": "ts",
            "id": "id",
            "process_name": "LOWER(process_name)",
            "src_ip": "src_ip",
            "dst_ip": "dst_ip",
            "src_port": "src_port",
            "dst_port": "dst_port",
            "proto": "proto",
            "length": "length",
            "source": "source",
        }
        field_sql = field_map.get(key, "ts")
        return f"{field_sql} {direction}, id {direction}"

    def _normalize_packet_rows(self, rows: list[dict]) -> list[dict]:
        for row in rows:
            row["ts_epoch"] = parse_ts_float(row.get("ts", 0.0))
            row["ts"] = render_ts_text(row.get("ts", ""))
        return rows

    def _build_packet_filter_sql(
        self,
        process_name: str = "",
        ip: str = "",
        source: str = "",
        extra_sql: str = "",
        extra_args: list | None = None,
    ) -> tuple[str, list[object]]:
        sql = ""
        query_args: list[object] = []
        if process_name:
            sql += " AND process_name LIKE ?"
            query_args.append(f"%{process_name}%")
        if ip:
            sql += " AND (src_ip LIKE ? OR dst_ip LIKE ?)"
            query_args.extend([f"%{ip}%", f"%{ip}%"])
        if source:
            sql += " AND source=?"
            query_args.append(source)
        elif self._offline_store_enabled():
            sql += " AND source <> 'offline'"
        if extra_sql:
            sql += extra_sql
            query_args.extend(list(extra_args or []))
        return sql, query_args

    def _count_packet_rows(self, process_name: str = "", ip: str = "", source: str = "", extra_sql: str = "", extra_args: list | None = None) -> int:
        if source == "offline" and self._offline_store_enabled():
            assert self.offline_packet_store is not None
            return self.offline_packet_store.count_packets(
                process_name=process_name,
                ip=ip,
                source="offline",
                extra_sql=extra_sql,
                extra_args=list(extra_args or []),
            )
        c = self.db.conn.cursor()
        sql = """
            SELECT COUNT(1)
            FROM captured_packets
            WHERE 1=1
        """
        filter_sql, query_args = self._build_packet_filter_sql(
            process_name=process_name,
            ip=ip,
            source=source,
            extra_sql=extra_sql,
            extra_args=extra_args,
        )
        sql += filter_sql
        c.execute(sql, tuple(query_args))
        row = c.fetchone()
        return int(row[0] if row else 0)

    def _query_packet_rows_chunk(
        self,
        limit: int,
        offset: int = 0,
        process_name: str = "",
        ip: str = "",
        source: str = "",
        extra_sql: str = "",
        extra_args: list | None = None,
        sort_key: str = "ts",
        sort_desc: bool = True,
    ) -> list[dict]:
        key = self._normalize_packet_sort_key(sort_key)
        if source == "offline" and self._offline_store_enabled():
            assert self.offline_packet_store is not None
            rows = self.offline_packet_store.query_packets(
                limit=limit,
                offset=offset,
                process_name=process_name,
                ip=ip,
                source="offline",
                extra_sql=extra_sql,
                extra_args=list(extra_args or []),
                sort_key=key,
                sort_desc=sort_desc,
            )
            return self._normalize_packet_rows(rows)
        c = self.db.conn.cursor()
        sql = """
            SELECT id, ts, src_ip, dst_ip, src_port, dst_port, proto, length, direction, process_id, process_name, source
            FROM captured_packets
            WHERE 1=1
        """
        filter_sql, query_args = self._build_packet_filter_sql(
            process_name=process_name,
            ip=ip,
            source=source,
            extra_sql=extra_sql,
            extra_args=extra_args,
        )
        sql += filter_sql
        sql += f" ORDER BY {self._build_packet_sort_sql(key, sort_desc)}"
        sql += " LIMIT ? OFFSET ?"
        query_args.extend([max(1, int(limit)), max(0, int(offset))])
        c.execute(sql, tuple(query_args))
        rows = [dict(r) for r in c.fetchall()]
        return self._normalize_packet_rows(rows)

    def query_packets_page(
        self,
        page: int = 1,
        page_size: int = 500,
        process_name: str = "",
        ip: str = "",
        source: str = "",
        rule_expr: str = "",
        only_abnormal: bool = False,
        sort_key: str = "ts",
        sort_desc: bool = True,
    ) -> dict:
        return packet_query_packets_page(
            self,
            page=page,
            page_size=page_size,
            process_name=process_name,
            ip=ip,
            source=source,
            rule_expr=rule_expr,
            only_abnormal=only_abnormal,
            sort_key=sort_key,
            sort_desc=sort_desc,
        )

    def query_packets_filtered(
        self,
        process_name: str = "",
        ip: str = "",
        source: str = "",
        rule_expr: str = "",
        only_abnormal: bool = False,
        sort_key: str = "ts",
        sort_desc: bool = True,
        max_rows: int = 20000,
    ) -> dict:
        return packet_query_packets_filtered(
            self,
            process_name=process_name,
            ip=ip,
            source=source,
            rule_expr=rule_expr,
            only_abnormal=only_abnormal,
            sort_key=sort_key,
            sort_desc=sort_desc,
            max_rows=max_rows,
        )

    def query_offline_frames_page(
        self,
        page: int = 1,
        page_size: int = 500,
        search_text: str = "",
        linktype: int = 0,
        rule_expr: str = "",
    ) -> dict:
        return packet_query_offline_frames_page(
            self,
            page=page,
            page_size=page_size,
            search_text=search_text,
            linktype=linktype,
            rule_expr=rule_expr,
        )

    def query_packets(self, limit: int | None = None, process_name: str = "", ip: str = "", source: str = "", rule_expr: str = "") -> list[dict]:
        extra_sql, extra_args = self._build_packet_rule_sql(rule_expr)
        rows: list[dict] = []
        if source == "offline" and self._offline_store_enabled():
            assert self.offline_packet_store is not None
            rows = self.offline_packet_store.query_packets(
                limit=limit,
                process_name=process_name,
                ip=ip,
                source="offline",
                extra_sql=extra_sql,
                extra_args=extra_args,
            )
        else:
            c = self.db.conn.cursor()
            sql = """
                SELECT id, ts, src_ip, dst_ip, src_port, dst_port, proto, length, direction, process_id, process_name, source
                FROM captured_packets
                WHERE 1=1
            """
            filter_sql, args = self._build_packet_filter_sql(
                process_name=process_name,
                ip=ip,
                source=source,
                extra_sql=extra_sql,
                extra_args=extra_args,
            )
            sql += filter_sql
            sql += " ORDER BY id DESC"
            if limit is not None and int(limit) > 0:
                sql += " LIMIT ?"
                args.append(int(limit))
            c.execute(sql, tuple(args))
            rows = [dict(r) for r in c.fetchall()]
        rows = self._normalize_packet_rows(rows)
        if not rows:
            return rows
        return self._attach_packet_risk(rows)

    def _attach_packet_risk(self, rows: list[dict]) -> list[dict]:
        if not rows:
            return rows
        c = self.db.conn.cursor()
        value_rows: list[str] = []
        args: list[object] = []
        flow_risk: dict[tuple[str, str, int, int, str, str], int] = {}
        for packet in rows:
            src = str(packet.get("src_ip", "") or "")
            dst = str(packet.get("dst_ip", "") or "")
            src_port = int(packet.get("src_port", 0) or 0)
            dst_port = int(packet.get("dst_port", 0) or 0)
            proto = str(packet.get("proto", "") or "").upper()
            source = str(packet.get("source", "live") or "live")
            key = (src, dst, src_port, dst_port, proto, source)
            if key in flow_risk:
                continue
            flow_risk[key] = 0
            value_rows.append("(?, ?, ?, ?, ?, ?)")
            args.extend([src, dst, src_port, dst_port, proto, source])
        if not value_rows:
            for row in rows:
                row["risk_level"] = "normal"
            return rows
        # 安全：VALUES 均为 ? 占位符，参数经 args 绑定（参数化查询）
        values_clause = ", ".join(value_rows)
        _sql = "\n".join(
            [
                "WITH requested_flows(src_ip, dst_ip, src_port, dst_port, proto, source) AS (",
                "    VALUES " + values_clause,
                ")",
                "SELECT summary.src_ip, summary.dst_ip, summary.src_port, summary.dst_port, "
                "summary.proto, summary.source, summary.max_level_rank",
                "FROM flow_risk_summary AS summary",
                "INNER JOIN requested_flows AS requested",
                "    ON summary.src_ip = requested.src_ip",
                "   AND summary.dst_ip = requested.dst_ip",
                "   AND summary.src_port = requested.src_port",
                "   AND summary.dst_port = requested.dst_port",
                "   AND summary.proto = requested.proto",
                "   AND summary.source = requested.source",
            ]
        )
        c.execute(_sql, tuple(args))
        for summary_row in c.fetchall():
            key = (
                str(summary_row["src_ip"] or ""),
                str(summary_row["dst_ip"] or ""),
                int(summary_row["src_port"] or 0),
                int(summary_row["dst_port"] or 0),
                str(summary_row["proto"] or "").upper(),
                str(summary_row["source"] or "live"),
            )
            flow_risk[key] = max(flow_risk.get(key, 0), int(summary_row["max_level_rank"] or 0))
        for row in rows:
            src = str(row["src_ip"] or "")
            dst = str(row["dst_ip"] or "")
            src_port = int(row.get("src_port", 0) or 0)
            dst_port = int(row.get("dst_port", 0) or 0)
            proto = str(row.get("proto", "") or "").upper()
            source = str(row.get("source", "live") or "live")
            rank = flow_risk.get((src, dst, src_port, dst_port, proto, source), 0)
            row["risk_level"] = rank_to_level(rank)
        return rows

    def _query_live_packets_by_ids(self, ids: Sequence[int]) -> list[dict]:
        normalized_ids = [int(i) for i in ids if int(i) > 0]
        if not normalized_ids:
            return []
        placeholders = ",".join(["?"] * len(normalized_ids))
        c = self.db.conn.cursor()
        c.execute(
            # 安全：id 均为 ? 占位符，参数经 tuple 绑定（参数化查询）
            "\n".join(
                [
                    "SELECT id, ts, src_ip, dst_ip, src_port, dst_port, proto, length, "
                    "direction, process_id, process_name, source",
                    "FROM captured_packets",
                    "WHERE id IN (" + placeholders + ")",
                    "ORDER BY id DESC",
                ]
            ),
            tuple(normalized_ids),
        )
        return [dict(r) for r in c.fetchall()]

    def query_packets_by_ids(self, packet_ids: list[int]) -> list[dict]:
        ids = [int(i) for i in packet_ids if int(i) > 0]
        if not ids:
            return []
        rows: list[dict]
        if self._offline_store_enabled():
            assert self.offline_packet_store is not None
            rows = self.offline_packet_store.query_packets_by_ids(ids)
            if not rows:
                rows = self._query_live_packets_by_ids(ids)
        else:
            rows = self._query_live_packets_by_ids(ids)
        return self._normalize_packet_rows(rows)

    def query_packet_detail(self, packet_id: int) -> dict | None:
        details = self.query_packet_details([packet_id], include_related_alerts=True)
        return details.get(int(packet_id))

    def _normalize_packet_detail_row(self, packet: dict) -> dict:
        packet["ts_epoch"] = parse_ts_float(packet.get("ts", 0.0))
        packet["ts"] = render_ts_text(packet.get("ts", ""))
        return packet

    def _query_related_alerts(self, packet: Mapping[str, object], limit: int = 5) -> list[dict]:
        c = self.db.conn.cursor()
        c.execute(
            """
            SELECT ts, level, reason, sub_category
            FROM alerts
            WHERE ((src_ip=? AND dst_ip=? AND src_port=? AND dst_port=? AND proto=?) OR (src_ip=? AND dst_ip=? AND src_port=? AND dst_port=? AND proto=?))
            ORDER BY id DESC
            LIMIT 5
            """,
            (
                packet.get("src_ip", ""),
                packet.get("dst_ip", ""),
                int(packet.get("src_port", 0) or 0),
                int(packet.get("dst_port", 0) or 0),
                str(packet.get("proto", "") or "").upper(),
                packet.get("dst_ip", ""),
                packet.get("src_ip", ""),
                int(packet.get("dst_port", 0) or 0),
                int(packet.get("src_port", 0) or 0),
                str(packet.get("proto", "") or "").upper(),
            ),
        )
        return [dict(r) for r in c.fetchall()[: max(1, int(limit))]]

    @staticmethod
    def _normalize_unique_ids(values: Sequence[int]) -> list[int]:
        out: list[int] = []
        seen: set[int] = set()
        for value in values:
            normalized = int(value or 0)
            if normalized > 0 and normalized not in seen:
                seen.add(normalized)
                out.append(normalized)
        return out

    def query_packet_details(self, packet_ids: Sequence[int], include_related_alerts: bool = False) -> dict[int, dict]:
        normalized_ids = self._normalize_unique_ids(packet_ids)
        if not normalized_ids:
            return {}

        results: dict[int, dict] = {}
        live_ids: list[int] = []
        offline_ids: list[int] = []
        offline_base = int(getattr(OfflinePacketStore, "OFFLINE_ID_BASE", 10_000_000_000))
        for packet_id in normalized_ids:
            if self._offline_store_enabled() and packet_id >= offline_base:
                offline_ids.append(packet_id)
            else:
                live_ids.append(packet_id)

        if live_ids:
            placeholders = ",".join(["?"] * len(live_ids))
            c = self.db.conn.cursor()
            c.execute(f"SELECT * FROM captured_packets WHERE id IN ({placeholders})", tuple(live_ids))  # nosec
            for row in c.fetchall():
                packet = self._normalize_packet_detail_row(dict(row))
                if include_related_alerts:
                    packet["related_alerts"] = self._query_related_alerts(packet)
                results[int(packet["id"])] = packet

        if offline_ids and self._offline_store_enabled():
            assert self.offline_packet_store is not None
            for packet in self.offline_packet_store.query_packet_details(offline_ids):
                normalized_packet = self._normalize_packet_detail_row(packet)
                normalized_packet["related_alerts"] = self._query_related_alerts(normalized_packet) if include_related_alerts else []
                results[int(normalized_packet["id"])] = normalized_packet

        return results

    def query_offline_frame_detail(self, frame_id: int) -> dict | None:
        details = self.query_offline_frame_details([frame_id])
        return details.get(int(frame_id))

    def query_offline_frame_details(self, frame_ids: Sequence[int]) -> dict[int, dict]:
        if not self._offline_store_enabled():
            return {}
        assert self.offline_packet_store is not None
        normalized_ids = self._normalize_unique_ids(frame_ids)
        if not normalized_ids:
            return {}
        details: dict[int, dict] = {}
        for frame in self.offline_packet_store.query_frame_details(normalized_ids):
            frame["ts_epoch"] = parse_ts_float(frame.get("ts", 0.0))
            frame["ts"] = render_ts_text(frame.get("ts", ""))
            frame["related_alerts"] = []
            details[int(frame["id"])] = frame
        return details

    def query_flow_packets(self, packet_id: int, limit: int = 3000) -> list[dict]:
        pid = int(packet_id)
        if self._offline_store_enabled() and pid >= int(getattr(OfflinePacketStore, "OFFLINE_ID_BASE", 10_000_000_000)):
            assert self.offline_packet_store is not None
            rows = self.offline_packet_store.query_flow_packets(pid, limit=limit)
            return self._normalize_packet_rows(rows)

        c = self.db.conn.cursor()
        c.execute(
            """
            WITH seed AS (
                SELECT src_ip, dst_ip, src_port, dst_port, proto, source
                FROM captured_packets
                WHERE id = ?
                LIMIT 1
            )
            SELECT p.id, p.ts, p.src_ip, p.dst_ip, p.src_port, p.dst_port, p.proto, p.length, p.process_name, p.raw_hex, p.source
            FROM captured_packets AS p
            INNER JOIN seed AS s
                ON p.proto = UPPER(COALESCE(s.proto, ''))
               AND (
                    (p.src_ip = s.src_ip AND p.dst_ip = s.dst_ip AND p.src_port = s.src_port AND p.dst_port = s.dst_port)
                    OR
                    (p.src_ip = s.dst_ip AND p.dst_ip = s.src_ip AND p.src_port = s.dst_port AND p.dst_port = s.src_port)
               )
               AND (COALESCE(s.source, '') = '' OR p.source = s.source)
            ORDER BY ts ASC, id ASC
            LIMIT ?
            """,
            (pid, max(1, int(limit))),
        )
        rows = [dict(r) for r in c.fetchall()]
        return self._normalize_packet_rows(rows)

    def analyze_flow(self, packet_id: int, limit: int = 3000, direction_mode: str = "interleaved") -> dict:
        rows = self.query_flow_packets(packet_id=packet_id, limit=limit)
        if not rows:
            return {
                "direction_mode": direction_mode,
                "segment_count": 0,
                "client_to_server": {"label": "C->S", "payload_bytes": b"", "payload_size": 0, "packet_ids": []},
                "server_to_client": {"label": "S->C", "payload_bytes": b"", "payload_size": 0, "packet_ids": []},
                "interleaved": {"label": "双向交错", "payload_bytes": b"", "payload_size": 0, "packet_ids": []},
                "segments": [],
                "candidates": [],
                "assets": [],
                "objects": [],
            }
        first = rows[0]
        return self.flow_workbench.analyze_flow(
            rows=rows,
            anchor_src=str(first.get("src_ip", "") or ""),
            anchor_sport=int(first.get("src_port", 0) or 0),
            direction_mode=str(direction_mode or "interleaved"),
        )

    def render_flow_stream_text(self, analysis: dict, mode: str = "ascii", direction_mode: str = "interleaved") -> str:
        return self.flow_workbench.render_stream_text(
            analysis=analysis,
            mode=str(mode or "ascii"),
            direction_mode=str(direction_mode or "interleaved"),
        )

    def export_flow_artifact(self, analysis: dict, output_path: Path, artifact: str, file_format: str) -> Path:
        return self.flow_workbench.export_flow_artifact(
            analysis=analysis,
            output_path=output_path,
            artifact=str(artifact or "interleaved"),
            file_format=str(file_format or "txt"),
        )

    def export_carved_object(self, object_row: dict, output_path: Path) -> Path:
        return self.flow_workbench.export_carved_object(object_row=object_row, output_path=output_path)

    def clear_packets_by_source(self, source: str) -> int:
        src = str(source or "").strip()
        if not src:
            return 0
        c = self.db.conn.cursor()
        c.execute("DELETE FROM captured_packets WHERE source=?", (src,))
        deleted = int(c.rowcount or 0)
        self.db.conn.commit()
        return deleted

    def clear_alerts_by_source(self, source: str) -> int:
        src = str(source or "").strip()
        if not src:
            return 0
        c = self.db.conn.cursor()
        c.execute("DELETE FROM alerts WHERE source=?", (src,))
        deleted = int(c.rowcount or 0)
        self.db.conn.commit()
        if deleted > 0:
            self.db.rebuild_flow_risk_summary(source=src, commit=True)
        return deleted

    def clear_offline_analysis_data(self, clear_alerts: bool = True) -> tuple[int, int]:
        if self._offline_store_enabled():
            assert self.offline_packet_store is not None
            deleted_packets = self.offline_packet_store.clear_source("offline")
        else:
            deleted_packets = self.clear_packets_by_source("offline")
        deleted_alerts = self.clear_alerts_by_source("offline") if clear_alerts else 0
        return deleted_packets, deleted_alerts

    def clear_realtime_monitor_data(self) -> tuple[int, int]:
        deleted_packets = self.clear_packets_by_source("live")
        deleted_alerts = self.clear_alerts_by_source("live")
        c = self.db.conn.cursor()
        c.execute("DELETE FROM traffic_stats")
        self.db.conn.commit()
        self.reset_realtime_summary()
        return deleted_packets, deleted_alerts

    def import_offline_pcap(self, pcap_path: Path, mode: str = "") -> tuple[int, int]:
        return run_offline_import(self, pcap_path, mode)

    def _import_offline_generic_frames(self, pcap_path: Path, parser_cfg: OfflineParserConfig, profile: OfflineImportProfile) -> int:
        if not self._offline_store_enabled():
            return 0
        assert self.offline_packet_store is not None
        total_frames = 0
        try:
            for frame_batch in iter_offline_generic_frames(pcap_path, parser_cfg):
                frames = list(frame_batch.frames)
                if not frames:
                    continue
                self.offline_packet_store.insert_frame_batch(
                    frames=frames,
                    preview_bytes=profile.raw_hex_preview_bytes,
                    source="offline",
                )
                total_frames += len(frames)
                self.offline_progress["generic_frames"] = total_frames
        except OfflineParserError:
            return total_frames
        return total_frames

    def _apply_offline_cpu_limit(self, profile: OfflineImportProfile) -> None:
        limit = int(profile.cpu_limit_percent or 0)
        if limit <= 0 or psutil is None:
            return
        now = time.perf_counter()
        if now - self._offline_cpu_last_sample < 0.08:
            return
        cpu = float(psutil.cpu_percent(interval=0.02))
        self._offline_cpu_last_sample = now
        if cpu <= limit:
            return
        overflow = max(0.0, cpu - float(limit))
        backoff = min(0.12, 0.01 + overflow / 100.0 * 0.08)
        time.sleep(backoff)

    def _flush_offline_feature_buffer(self, force: bool = False) -> int:
        if not self._offline_feature_buffer:
            return 0
        if not force and len(self._offline_feature_buffer) < self._offline_feature_flush_size:
            return 0
        features = self._offline_feature_buffer
        self._offline_feature_buffer = []
        alerts = self.detector.process(features, source="offline", db_commit=not self._offline_write_transaction_open)
        return len(alerts)

    def _process_offline_batch(self, packets: Sequence[Mapping[str, object]], profile: OfflineImportProfile) -> int:
        if not packets:
            return 0
        if profile.store_packets:
            if isinstance(packets, LegacyPacketBatchView):
                self._store_captured_packets_from_columns(
                    packets,
                    source="offline",
                    preview_bytes=profile.raw_hex_preview_bytes,
                    store_raw_hex=profile.store_raw_hex,
                    commit=not self._offline_write_transaction_open,
                )
            else:
                self._store_captured_packets(
                    packets,
                    source="offline",
                    preview_bytes_override=profile.raw_hex_preview_bytes,
                    store_raw_hex_override=profile.store_raw_hex,
                    commit=not self._offline_write_transaction_open,
                )
        if not profile.enable_detection:
            if self._offline_write_transaction_open:
                self._flush_offline_write_if_needed()
            return 0
        self.aggregator.ingest_batch(packets)
        try:
            now_ts = max(float(p.get("ts", 0.0) or 0.0) for p in packets)
        except Exception:
            now_ts = time.time()
        if now_ts <= 0:
            now_ts = time.time()
        self.aggregator.cleanup_expired(now_ts, CONFIG.session_timeout_seconds)
        self._offline_detection_batch_counter += 1
        if (self._offline_detection_batch_counter % max(1, int(profile.detection_flush_interval_batches))) != 0:
            if self._offline_write_transaction_open:
                self._flush_offline_write_if_needed()
            return 0
        features = self.aggregator.flush_features(now_ts)
        if features:
            self._offline_feature_buffer.extend(features)
        alerts_count = self._flush_offline_feature_buffer(force=False)
        if self._offline_write_transaction_open:
            self._flush_offline_write_if_needed()
        return alerts_count

    def _flush_remaining_offline_features(self) -> int:
        now_ts = time.time()
        features = self.aggregator.flush_features(now_ts)
        if not features:
            return 0
        self._offline_feature_buffer.extend(features)
        return 0

    def _store_captured_packets_from_columns(
        self,
        packets: LegacyPacketBatchView,
        source: str,
        preview_bytes: int,
        store_raw_hex: bool,
        commit: bool = True,
    ) -> None:
        row_count = int(getattr(packets, "row_count", 0) or 0)
        if row_count <= 0:
            return
        if source == "offline" and self._offline_store_enabled():
            assert self.offline_packet_store is not None
            self.offline_packet_store.insert_legacy_batch(
                packets=packets,
                preview_bytes=preview_bytes,
                store_raw_hex=store_raw_hex,
                source=source,
            )
            return
        ts_col = packets.get_column("ts") or []
        src_ip_col = packets.get_column("src_ip") or []
        dst_ip_col = packets.get_column("dst_ip") or []
        src_port_col = packets.get_column("src_port") or []
        dst_port_col = packets.get_column("dst_port") or []
        proto_col = packets.get_column("proto") or []
        len_col = packets.get_column("length") or []
        direction_col = packets.get_column("direction") or []
        process_id_col = packets.get_column("process_id") or []
        process_name_col = packets.get_column("process_name") or []
        raw_hex_col = packets.get_column("raw_hex") or []
        max_hex = max(0, int(preview_bytes)) * 2
        rows: list[tuple] = []
        rows_extend = rows.append
        for i in range(row_count):
            ts_value = 0.0
            if i < len(ts_col):
                try:
                    ts_value = float(ts_col[i] or 0.0)
                except Exception:
                    ts_value = 0.0
            raw_hex = ""
            if store_raw_hex and i < len(raw_hex_col):
                raw_hex = str(raw_hex_col[i] or "")
                if max_hex > 0:
                    raw_hex = raw_hex[:max_hex]
            rows_extend(
                (
                    ts_value,
                    str(src_ip_col[i] if i < len(src_ip_col) else ""),
                    str(dst_ip_col[i] if i < len(dst_ip_col) else ""),
                    int(src_port_col[i] if i < len(src_port_col) else 0),
                    int(dst_port_col[i] if i < len(dst_port_col) else 0),
                    str(proto_col[i] if i < len(proto_col) else "OTHER"),
                    int(len_col[i] if i < len(len_col) else 0),
                    str(direction_col[i] if i < len(direction_col) else "offline"),
                    int(process_id_col[i] if i < len(process_id_col) else 0),
                    str(process_name_col[i] if i < len(process_name_col) else ""),
                    raw_hex,
                    source,
                )
            )
        c = self.db.conn.cursor()
        c.executemany(
            """
            INSERT INTO captured_packets(ts, src_ip, dst_ip, src_port, dst_port, proto, length, direction, process_id, process_name, raw_hex, source)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            rows,
        )
        if commit:
            self.db.conn.commit()

    def _current_alert_max_id(self) -> int:
        c = self.db.conn.cursor()
        c.execute("SELECT COALESCE(MAX(id), 0) AS max_id FROM alerts")
        row = c.fetchone()
        return int(row["max_id"]) if row else 0

    def _count_new_alerts(self, start_alert_id: int, source: str = "") -> int:
        c = self.db.conn.cursor()
        if source:
            c.execute("SELECT COUNT(1) AS cnt FROM alerts WHERE id > ? AND source = ?", (int(start_alert_id), source))
        else:
            c.execute("SELECT COUNT(1) AS cnt FROM alerts WHERE id > ?", (int(start_alert_id),))
        row = c.fetchone()
        return int(row["cnt"]) if row else 0

    def export_packets(self, rows: list[dict], output_path: Path, file_format: str) -> Path:
        fmt = file_format.lower()
        if fmt == "json":
            import json

            output_path.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
            return output_path
        if fmt == "csv":
            import csv

            fields = ["id", "ts", "source", "src_ip", "src_port", "dst_ip", "dst_port", "proto", "length", "direction", "process_name"]
            with output_path.open("w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fields)
                writer.writeheader()
                for row in rows:
                    writer.writerow({k: row.get(k, "") for k in fields})
            return output_path
        if fmt == "pcap":
            from scapy.layers.inet import ICMP, IP, TCP, UDP
            from scapy.layers.l2 import Ether
            from scapy.packet import Raw
            from scapy.utils import wrpcap

            packets = []
            for row in rows:
                raw_hex = str(row.get("raw_hex", "") or "").strip()
                if raw_hex:
                    try:
                        raw_bytes = bytes.fromhex(raw_hex)
                    except Exception:
                        raw_bytes = b""
                    if raw_bytes:
                        try:
                            packets.append(Ether(raw_bytes))
                            continue
                        except Exception:
                            try:
                                packets.append(IP(raw_bytes))
                                continue
                            except Exception:
                                packets.append(Raw(raw_bytes))
                                continue
                src_ip = str(row.get("src_ip", "") or "0.0.0.0")  # nosec
                dst_ip = str(row.get("dst_ip", "") or "0.0.0.0")  # nosec
                proto = str(row.get("proto", "OTHER")).upper()
                src_port = int(row.get("src_port", 0) or 0)
                dst_port = int(row.get("dst_port", 0) or 0)
                if proto == "TCP":
                    packets.append(IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port))
                elif proto == "UDP":
                    packets.append(IP(src=src_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port))
                elif proto == "ICMP":
                    packets.append(IP(src=src_ip, dst=dst_ip) / ICMP())
            if packets:
                wrpcap(str(output_path), packets)
            else:
                output_path.write_bytes(b"")
            return output_path
        raise ValueError("不支持的导出格式")

    def expand_packet_rows(self, rows: Sequence[dict], detail_batch_size: int = 400) -> list[dict]:
        if not rows:
            return []
        base_by_id = {int(row.get("id", 0) or 0): dict(row) for row in rows if int(row.get("id", 0) or 0) > 0}
        packet_ids = list(base_by_id.keys())
        expanded: list[dict] = []
        batch_size = max(50, min(800, int(detail_batch_size or 400)))
        for offset in range(0, len(packet_ids), batch_size):
            batch = packet_ids[offset : offset + batch_size]
            detail_map = self.query_packet_details(batch, include_related_alerts=False)
            for packet_id in batch:
                detail = dict(detail_map.get(packet_id) or {})
                if not detail:
                    detail = dict(base_by_id.get(packet_id, {}))
                base = base_by_id.get(packet_id, {})
                if "risk_level" not in detail:
                    detail["risk_level"] = base.get("risk_level", "normal")
                if "source" not in detail:
                    detail["source"] = base.get("source", "")
                expanded.append(detail)
        return expanded

    def extract_packet_fields(self, rows: Sequence[dict], detail_batch_size: int = 400) -> list[dict]:
        return self.packet_batch_export.extract_field_rows(self.expand_packet_rows(rows, detail_batch_size=detail_batch_size))

    def export_packet_fields(self, rows: list[dict], output_path: Path, file_format: str) -> Path:
        return self.packet_batch_export.export_field_rows(rows, output_path, file_format)

    def extract_packet_flows(self, rows: Sequence[dict], detail_batch_size: int = 400) -> list[dict]:
        return self.packet_batch_export.extract_flow_rows(self.expand_packet_rows(rows, detail_batch_size=detail_batch_size))

    def export_packet_flows(self, rows: list[dict], output_path: Path, file_format: str) -> Path:
        return self.packet_batch_export.export_flow_rows(rows, output_path, file_format)

    def extract_packet_candidates(self, rows: Sequence[dict], detail_batch_size: int = 400) -> list[dict]:
        return self.packet_batch_export.extract_candidate_rows(self.expand_packet_rows(rows, detail_batch_size=detail_batch_size))

    def export_packet_candidates(self, rows: list[dict], output_path: Path, file_format: str) -> Path:
        return self.packet_batch_export.export_candidate_rows(rows, output_path, file_format)

    def extract_packet_http_interactions(self, rows: Sequence[dict], detail_batch_size: int = 400) -> list[dict]:
        return self.packet_batch_export.extract_http_interaction_rows(
            self.expand_packet_rows(rows, detail_batch_size=detail_batch_size)
        )

    def export_packet_http_interactions(self, rows: list[dict], output_path: Path, file_format: str) -> Path:
        return self.packet_batch_export.export_http_interaction_rows(rows, output_path, file_format)

    def extract_packet_http_variants(self, rows: Sequence[dict], detail_batch_size: int = 400) -> list[dict]:
        return self.packet_batch_export.extract_http_variant_rows(self.expand_packet_rows(rows, detail_batch_size=detail_batch_size))

    def export_packet_http_variants(self, rows: list[dict], output_path: Path, file_format: str) -> Path:
        return self.packet_batch_export.export_http_variant_rows(rows, output_path, file_format)

    def export_packet_flow_body_bundle(self, rows: Sequence[dict], output_dir: Path, detail_batch_size: int = 400) -> Path:
        return self.packet_batch_export.export_flow_body_bundle(
            self.expand_packet_rows(rows, detail_batch_size=detail_batch_size),
            output_dir=output_dir,
        )

    def get_alert_breakdown(self, source: str = "") -> dict:
        c = self.db.conn.cursor()
        if source:
            c.execute("SELECT level, COUNT(*) AS cnt FROM alerts WHERE source=? GROUP BY level", (source,))
        else:
            c.execute("SELECT level, COUNT(*) AS cnt FROM alerts GROUP BY level")
        by_level = {r["level"]: r["cnt"] for r in c.fetchall()}
        if source:
            c.execute("SELECT src_ip, COUNT(*) AS cnt FROM alerts WHERE source=? GROUP BY src_ip ORDER BY cnt DESC LIMIT 10", (source,))
        else:
            c.execute("SELECT src_ip, COUNT(*) AS cnt FROM alerts GROUP BY src_ip ORDER BY cnt DESC LIMIT 10")
        top_ips = [[r["src_ip"], r["cnt"]] for r in c.fetchall()]
        return {"by_level": by_level, "top_ips": top_ips}

    def get_attack_stats(self, limit: int = 10, source: str = "") -> list[dict]:
        c = self.db.conn.cursor()
        sql = """
            SELECT sub_category, COUNT(*) AS cnt
            FROM alerts
            WHERE sub_category IS NOT NULL AND sub_category <> ''
        """
        args: list = []
        if source:
            sql += " AND source=?"
            args.append(source)
        sql += " GROUP BY sub_category ORDER BY cnt DESC LIMIT ?"
        args.append(limit)
        c.execute(sql, tuple(args))
        return [dict(r) for r in c.fetchall()]

    def get_learning_status(self) -> dict:
        return {
            "in_learning": self.detector.in_learning(),
            "remaining_seconds": self.detector.learning_remaining_seconds(),
            "fast_seconds": CONFIG.baseline_fast_seconds,
            "standard_seconds": CONFIG.baseline_standard_seconds,
        }

    def get_environment_summary(self) -> dict:
        pydivert_ok = False
        try:
            import pydivert  # noqa: F401

            pydivert_ok = True
        except Exception:
            pydivert_ok = False
        interfaces = self.capture.list_interfaces()
        vm_count = sum(1 for i in interfaces if "vmware" in i["display_name"].lower() or "virtual" in i["display_name"].lower())
        host_ip = ""
        try:
            host_ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            host_ip = ""
        return {"pydivert_ok": pydivert_ok, "interface_count": len(interfaces), "vm_interface_count": vm_count, "host_ip": host_ip}

    def get_database_routing_summary(self) -> dict:
        offline_engine = "duckdb" if self._offline_store_enabled() else "sqlite"
        return {
            "offline_packets": {
                "engine": offline_engine,
                "owner": "offline_import_and_query",
                "notes": "大体量离线包明细优先使用DuckDB；禁用时回退SQLite。",
            },
            "alerts": {
                "engine": "sqlite",
                "owner": "detection_pipeline",
                "notes": "告警、规则匹配结果、审计关联依旧走SQLite。",
            },
            "core_business": {
                "engine": "sqlite",
                "owner": "auth_audit_lists_stats",
                "notes": "账号、审计、白黑名单、实时统计等事务型数据统一保留SQLite。",
            },
            "id_policy": {
                "offline_packet_id_base": int(getattr(OfflinePacketStore, "OFFLINE_ID_BASE", 10_000_000_000)),
                "notes": "离线包ID加偏移，避免与SQLite captured_packets主键冲突。",
            },
        }

    @staticmethod
    def _is_valid_ipv4(ip: str) -> bool:
        try:
            parsed = ipaddress.ip_address(str(ip or "").strip())
        except ValueError:
            return False
        return parsed.version == 4

    @staticmethod
    def _firewall_rule_base(ip: str) -> str:
        return f"AI_Traffic_Guard_Block_{ip}"

    @staticmethod
    def _run_netsh(args: list[str]) -> tuple[bool, str]:
        res, stdout_text, stderr_text = run_command_capture(["netsh", *args])
        output = (stderr_text or stdout_text or "").strip()
        return res.returncode == 0, output

    def _ensure_firewall_block_rules(self, ip: str) -> tuple[bool, str]:
        base = self._firewall_rule_base(ip)
        cmds = [
            ["advfirewall", "firewall", "add", "rule", f'name="{base}_OUT"', "dir=out", "action=block", f"remoteip={ip}"],
            ["advfirewall", "firewall", "add", "rule", f'name="{base}_IN"', "dir=in", "action=block", f"remoteip={ip}"],
        ]
        for cmd in cmds:
            ok, msg = self._run_netsh(cmd)
            if not ok:
                return False, msg or "防火墙规则写入失败，请以管理员权限运行"
        return True, ""

    def _remove_firewall_block_rules(self, ip: str) -> tuple[bool, str]:
        base = self._firewall_rule_base(ip)
        cmds = [
            ["advfirewall", "firewall", "delete", "rule", f'name="{base}_OUT"'],
            ["advfirewall", "firewall", "delete", "rule", f'name="{base}_IN"'],
        ]
        errors: list[str] = []
        for cmd in cmds:
            ok, msg = self._run_netsh(cmd)
            if ok:
                continue
            low = msg.lower()
            # 规则已不存在时视为幂等成功。
            if "no rules match" in low or "没有与指定标准匹配的规则" in low:
                continue
            errors.append(msg or "防火墙规则删除失败")
        if errors:
            return False, " | ".join(errors)
        return True, ""

    def _load_enabled_blacklist_ips(self) -> set[str]:
        c = self.db.conn.cursor()
        c.execute("SELECT DISTINCT ip FROM blacklist_whitelist WHERE list_type='black' AND enabled=1")
        ips: set[str] = set()
        for row in c.fetchall():
            ip = str(row["ip"] or "").strip()
            if self._is_valid_ipv4(ip):
                ips.add(ip)
        return ips

    def _load_managed_firewall_blocked_ips(self) -> set[str]:
        ok, output = self._run_netsh(["advfirewall", "firewall", "show", "rule", "name=all"])
        if not ok:
            return set()
        found = re.findall(r"AI_Traffic_Guard_Block_(\d{1,3}(?:\.\d{1,3}){3})_(?:IN|OUT)", output or "")
        return {ip for ip in found if self._is_valid_ipv4(ip)}

    def _bootstrap_firewall_blacklist_sync(self) -> None:
        db_ips = self._load_enabled_blacklist_ips()
        fw_ips = self._load_managed_firewall_blocked_ips()
        if fw_ips:
            for ip in fw_ips - db_ips:
                self._remove_firewall_block_rules(ip)
        for ip in db_ips:
            self._ensure_firewall_block_rules(ip)
        self.blocked_ips = set(db_ips)
        self.last_summary["firewall_blocks"] = len(self.blocked_ips)

    def _has_enabled_blacklist_entry(self, ip: str, exclude_item_id: int | None = None) -> bool:
        target = str(ip or "").strip()
        if not target:
            return False
        c = self.db.conn.cursor()
        if exclude_item_id is None:
            c.execute(
                "SELECT COUNT(1) AS cnt FROM blacklist_whitelist WHERE ip=? AND list_type='black' AND enabled=1",
                (target,),
            )
        else:
            c.execute(
                "SELECT COUNT(1) AS cnt FROM blacklist_whitelist WHERE ip=? AND list_type='black' AND enabled=1 AND id<>?",
                (target, int(exclude_item_id)),
            )
        row = c.fetchone()
        return bool(int(row["cnt"] or 0)) if row else False

    def upsert_blacklist_with_firewall(self, ip: str, enabled: int, remark: str, operator: str) -> tuple[bool, str]:
        target = (ip or "").strip()
        if not self._is_valid_ipv4(target):
            return False, "IP格式无效"
        is_enabled = int(enabled) == 1
        if is_enabled:
            ok, msg = self._ensure_firewall_block_rules(target)
            if not ok:
                return False, msg
            self.blocked_ips.add(target)
        else:
            ok, msg = self._remove_firewall_block_rules(target)
            if not ok:
                return False, msg
            self.blocked_ips.discard(target)
        self.list_service.upsert(target, "black", 1 if is_enabled else 0, remark)
        self.last_summary["firewall_blocks"] = len(self.blocked_ips)
        self.audit.log(operator, "blacklist_firewall_sync", target, f"enabled={1 if is_enabled else 0}")
        return True, "同步成功"

    def update_list_item_with_firewall(self, item_id: int, enabled: int, remark: str, operator: str) -> tuple[bool, str]:
        c = self.db.conn.cursor()
        c.execute("SELECT ip, list_type, enabled FROM blacklist_whitelist WHERE id=?", (int(item_id),))
        row = c.fetchone()
        if not row:
            return False, "名单项不存在"
        ip = str(row["ip"] or "").strip()
        list_type = str(row["list_type"] or "").strip().lower()
        prev_enabled = 1 if int(row["enabled"] or 0) == 1 else 0
        target_enabled = 1 if int(enabled) == 1 else 0
        if list_type == "black" and self._is_valid_ipv4(ip):
            if target_enabled == 1:
                ok, msg = self._ensure_firewall_block_rules(ip)
                if not ok:
                    return False, msg
                self.blocked_ips.add(ip)
            elif prev_enabled == 1 and not self._has_enabled_blacklist_entry(ip, exclude_item_id=int(item_id)):
                ok, msg = self._remove_firewall_block_rules(ip)
                if not ok:
                    return False, msg
                self.blocked_ips.discard(ip)
        self.list_service.update_item(int(item_id), target_enabled, remark)
        if list_type == "black" and self._is_valid_ipv4(ip) and self._has_enabled_blacklist_entry(ip):
            self.blocked_ips.add(ip)
        self.last_summary["firewall_blocks"] = len(self.blocked_ips)
        self.audit.log(operator, "blacklist_firewall_sync", ip or str(item_id), f"enabled={target_enabled}")
        return True, "同步成功"

    def delete_list_item_with_firewall(self, item_id: int, operator: str) -> tuple[bool, str]:
        c = self.db.conn.cursor()
        c.execute("SELECT ip, list_type, enabled FROM blacklist_whitelist WHERE id=?", (int(item_id),))
        row = c.fetchone()
        if not row:
            return False, "名单项不存在"
        ip = str(row["ip"] or "").strip()
        list_type = str(row["list_type"] or "").strip().lower()
        enabled = 1 if int(row["enabled"] or 0) == 1 else 0
        if list_type == "black" and enabled == 1 and self._is_valid_ipv4(ip) and not self._has_enabled_blacklist_entry(ip, exclude_item_id=int(item_id)):
            ok, msg = self._remove_firewall_block_rules(ip)
            if not ok:
                return False, msg
            self.blocked_ips.discard(ip)
        self.list_service.delete(int(item_id))
        if list_type == "black" and self._is_valid_ipv4(ip) and self._has_enabled_blacklist_entry(ip):
            self.blocked_ips.add(ip)
        self.last_summary["firewall_blocks"] = len(self.blocked_ips)
        self.audit.log(operator, "blacklist_firewall_sync", ip or str(item_id), "enabled=0,delete=1")
        return True, "同步成功"

    def block_ip_with_firewall(self, ip: str, operator: str) -> tuple[bool, str]:
        target = (ip or "").strip()
        if not self._is_valid_ipv4(target):
            return False, "IP格式无效"
        ok, msg = self._ensure_firewall_block_rules(target)
        if not ok:
            return False, msg or "防火墙规则写入失败，请以管理员权限运行"
        self.blocked_ips.add(target)
        self.list_service.upsert(target, "black", 1, "firewall_auto_block")
        self.audit.log(operator, "firewall_block_ip", target, "desktop_one_click")
        self.last_summary["firewall_blocks"] = len(self.blocked_ips)
        return True, "封禁成功"

    def generate_security_report(self, operator: str, source: str) -> Path:
        report_source = "offline" if str(source or "").strip().lower() == "offline" else "live"
        path = self.report_service.generate_visual_report(source=report_source)
        self.audit.log(operator, "report_generate", str(path), f"visual_security_report:{report_source}")
        return path
