import queue
import re
import sqlite3
import socket
import subprocess
import threading
import time
import os
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

try:
    import psutil
except Exception:  # pragma: no cover - optional runtime dependency
    psutil = None

from src.config import CONFIG
from src.core.aggregation.session_aggregator import SessionAggregator
from src.core.audit.service import AuditService
from src.core.capture.capture_engine import CaptureEngine
from src.core.detection.model_engine import ModelEngine
from src.core.detection.rule_engine import RuleEngine
from src.core.detection.service import DetectionService
from src.core.detection.attack_knowledge import get_attack_knowledge
from src.core.notify.service import NotificationService
from src.core.offline import OfflineParserConfig, OfflineParserError, iter_offline_batches
from src.core.offline.adapter import LegacyPacketBatchView
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


class AppRuntime:
    def __init__(self) -> None:
        self.db = Database()
        self.audit = AuditService(self.db)
        self.list_service = ListService(self.db)
        self.model_engine = ModelEngine(CONFIG.model_path)
        self.rule_engine = RuleEngine()
        self.detector = DetectionService(self.db, self.list_service, self.model_engine, self.rule_engine)
        self.notifier = NotificationService()
        self.report_service = ReportService(self.db)
        self.offline_packet_store: OfflinePacketStore | None = None
        if bool(getattr(CONFIG, "offline_use_duckdb", True)):
            try:
                self.offline_packet_store = OfflinePacketStore(Path(getattr(CONFIG, "offline_duckdb_path", Path("data/offline_packets.duckdb"))))
            except Exception:
                self.offline_packet_store = None
        self.packet_queue: queue.Queue = queue.Queue(maxsize=10000)
        self.capture = CaptureEngine(self.packet_queue)
        self.aggregator = SessionAggregator()
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
            self.worker = threading.Thread(target=self._worker_loop, daemon=True)
            self.worker.start()

    def stop_capture(self) -> None:
        self.capture.stop()
        self.running = False
        # 停止环境预识别（学习模式）
        self.detector.learning_until = 0

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
            self._save_traffic_stat()

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

    def _save_traffic_stat(self) -> None:
        c = self.db.conn.cursor()
        c.execute(
            "INSERT INTO traffic_stats(ts, inbound_packets, outbound_packets, active_sessions) VALUES(?,?,?,?)",
            (now_text(), self.last_summary["total_packets"], 0, self.last_summary["active_sessions"]),
        )
        self.db.conn.commit()
        self.db.cleanup_old_logs()

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
    def _level_rank(level: str) -> int:
        lv = (level or "").lower()
        if lv == "high":
            return 3
        if lv == "medium":
            return 2
        if lv == "low":
            return 1
        return 0

    @staticmethod
    def _rank_level(rank: int) -> str:
        if rank >= 3:
            return "high"
        if rank == 2:
            return "medium"
        if rank == 1:
            return "low"
        return "normal"

    @staticmethod
    def _render_ts_text(value: object) -> str:
        text = str(value or "").strip()
        if not text:
            return ""
        try:
            ts = float(text)
            return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return text

    @staticmethod
    def _parse_ts_float(value: object) -> float:
        try:
            return float(value or 0.0)
        except Exception:
            return 0.0

    @staticmethod
    def _build_packet_rule_sql(expression: str) -> tuple[str, list]:
        expr = str(expression or "").strip()
        if not expr:
            return "", []
        # 仅支持可安全下推到SQL的子集；其余情况由上层Python过滤兜底。
        if "||" in expr or "!" in expr:
            return "", []
        parts = [p.strip() for p in expr.split("&&") if p.strip()]
        if not parts:
            return "", []
        clauses: list[str] = []
        args: list = []
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
                if field in {"process", "process_name"}:
                    clauses.append("process_name LIKE ?")
                    args.append(f"%{value}%")
                elif field in {"ip", "ip.addr"}:
                    clauses.append("(src_ip LIKE ? OR dst_ip LIKE ?)")
                    args.extend([f"%{value}%", f"%{value}%"])
                elif field in {"proto", "source"}:
                    clauses.append(f"{field} LIKE ?")
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
            if field in {"ip.src", "src_ip"}:
                clauses.append(f"src_ip {op_sql} ?")
                args.append(value_raw)
            elif field in {"ip.dst", "dst_ip"}:
                clauses.append(f"dst_ip {op_sql} ?")
                args.append(value_raw)
            elif field in {"ip.addr", "ip"}:
                clauses.append(f"(src_ip {op_sql} ? OR dst_ip {op_sql} ?)")
                args.extend([value_raw, value_raw])
            elif field in {"port", "tcp.port", "udp.port"}:
                try:
                    v = int(float(value_raw))
                except Exception:
                    return "", []
                clauses.append(f"(src_port {op_sql} ? OR dst_port {op_sql} ?)")
                args.extend([v, v])
            elif field in {"tcp.srcport", "udp.srcport", "src_port"}:
                try:
                    v = int(float(value_raw))
                except Exception:
                    return "", []
                clauses.append(f"src_port {op_sql} ?")
                args.append(v)
            elif field in {"tcp.dstport", "udp.dstport", "dst_port"}:
                try:
                    v = int(float(value_raw))
                except Exception:
                    return "", []
                clauses.append(f"dst_port {op_sql} ?")
                args.append(v)
            elif field in {"frame.len", "len", "length"}:
                try:
                    v = int(float(value_raw))
                except Exception:
                    return "", []
                clauses.append(f"length {op_sql} ?")
                args.append(v)
            elif field in {"frame.number"}:
                try:
                    v = int(float(value_raw))
                except Exception:
                    return "", []
                clauses.append(f"id {op_sql} ?")
                args.append(v)
            elif field in {"process", "process_name"}:
                clauses.append(f"process_name {op_sql} ?")
                args.append(value_raw)
            elif field in {"proto", "source"}:
                clauses.append(f"{field} {op_sql} ?")
                args.append(value_raw.upper() if field == "proto" else value_raw)
            elif field in {"id"}:
                try:
                    v = int(float(value_raw))
                except Exception:
                    return "", []
                clauses.append(f"id {op_sql} ?")
                args.append(v)
            else:
                return "", []
        if not clauses:
            return "", []
        return " AND " + " AND ".join(f"({c})" for c in clauses), args

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
            args: list = []
            if process_name:
                sql += " AND process_name LIKE ?"
                args.append(f"%{process_name}%")
            if ip:
                sql += " AND (src_ip LIKE ? OR dst_ip LIKE ?)"
                args.extend([f"%{ip}%", f"%{ip}%"])
            if source:
                sql += " AND source=?"
                args.append(source)
            elif self._offline_store_enabled():
                sql += " AND source <> 'offline'"
            if extra_sql:
                sql += extra_sql
                args.extend(extra_args)
            sql += " ORDER BY id DESC"
            if limit is not None and int(limit) > 0:
                sql += " LIMIT ?"
                args.append(int(limit))
            c.execute(sql, tuple(args))
            rows = [dict(r) for r in c.fetchall()]
        for row in rows:
            row["ts_epoch"] = self._parse_ts_float(row.get("ts", 0.0))
            row["ts"] = self._render_ts_text(row.get("ts", ""))
        if not rows:
            return rows
        return self._attach_packet_risk(rows)

    def _attach_packet_risk(self, rows: list[dict]) -> list[dict]:
        if not rows:
            return rows
        ips = {str(r.get("src_ip", "") or "") for r in rows} | {str(r.get("dst_ip", "") or "") for r in rows}
        ips.discard("")
        if not ips:
            for row in rows:
                row["risk_level"] = "normal"
            return rows
        c = self.db.conn.cursor()
        placeholders = ",".join(["?"] * len(ips))
        alert_sql = f"""
            SELECT src_ip, dst_ip, src_port, dst_port, proto, level, ts
            FROM alerts
            WHERE (src_ip IN ({placeholders}) OR dst_ip IN ({placeholders}))
            ORDER BY id DESC
            LIMIT 8000
        """
        alert_args = tuple(ips) + tuple(ips)
        c.execute(alert_sql, alert_args)
        flow_risk: dict[tuple[str, str, int, int, str], int] = {}
        for row in c.fetchall():
            src = str(row["src_ip"] or "")
            dst = str(row["dst_ip"] or "")
            src_port = int(row["src_port"] or 0)
            dst_port = int(row["dst_port"] or 0)
            proto = str(row["proto"] or "").upper()
            rank = self._level_rank(str(row["level"] or ""))
            key = (src, dst, src_port, dst_port, proto)
            rev = (dst, src, dst_port, src_port, proto)
            flow_risk[key] = max(rank, flow_risk.get(key, 0))
            flow_risk[rev] = max(rank, flow_risk.get(rev, 0))
        for row in rows:
            src = str(row["src_ip"] or "")
            dst = str(row["dst_ip"] or "")
            src_port = int(row.get("src_port", 0) or 0)
            dst_port = int(row.get("dst_port", 0) or 0)
            proto = str(row.get("proto", "") or "").upper()
            rank = flow_risk.get((src, dst, src_port, dst_port, proto), 0)
            row["risk_level"] = self._rank_level(rank)
        return rows

    def query_packets_by_ids(self, packet_ids: list[int]) -> list[dict]:
        ids = [int(i) for i in packet_ids if int(i) > 0]
        if not ids:
            return []
        rows: list[dict]
        if self._offline_store_enabled():
            assert self.offline_packet_store is not None
            rows = self.offline_packet_store.query_packets_by_ids(ids)
            if not rows:
                placeholders = ",".join(["?"] * len(ids))
                c = self.db.conn.cursor()
                c.execute(
                    f"""
                    SELECT id, ts, src_ip, dst_ip, src_port, dst_port, proto, length, direction, process_id, process_name, source
                    FROM captured_packets
                    WHERE id IN ({placeholders})
                    ORDER BY id DESC
                    """,
                    tuple(ids),
                )
                rows = [dict(r) for r in c.fetchall()]
        else:
            placeholders = ",".join(["?"] * len(ids))
            c = self.db.conn.cursor()
            c.execute(
                f"""
                SELECT id, ts, src_ip, dst_ip, src_port, dst_port, proto, length, direction, process_id, process_name, source
                FROM captured_packets
                WHERE id IN ({placeholders})
                ORDER BY id DESC
                """,
                tuple(ids),
            )
            rows = [dict(r) for r in c.fetchall()]
        for row in rows:
            row["ts_epoch"] = self._parse_ts_float(row.get("ts", 0.0))
            row["ts"] = self._render_ts_text(row.get("ts", ""))
        return rows

    def query_packet_detail(self, packet_id: int) -> dict | None:
        c = self.db.conn.cursor()
        c.execute("SELECT * FROM captured_packets WHERE id=?", (packet_id,))
        row = c.fetchone()
        packet: dict | None = dict(row) if row else None
        if not packet and self._offline_store_enabled():
            assert self.offline_packet_store is not None
            packet = self.offline_packet_store.query_packet_detail(int(packet_id))
        if not packet:
            return None
        packet["ts_epoch"] = self._parse_ts_float(packet.get("ts", 0.0))
        packet["ts"] = self._render_ts_text(packet.get("ts", ""))
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
        packet["related_alerts"] = [dict(r) for r in c.fetchall()]
        return packet

    def query_flow_packets(self, packet_id: int, limit: int = 3000) -> list[dict]:
        pid = int(packet_id)
        if self._offline_store_enabled() and pid >= int(getattr(OfflinePacketStore, "OFFLINE_ID_BASE", 10_000_000_000)):
            assert self.offline_packet_store is not None
            rows = self.offline_packet_store.query_flow_packets(pid, limit=limit)
            for row in rows:
                row["ts_epoch"] = self._parse_ts_float(row.get("ts", 0.0))
                row["ts"] = self._render_ts_text(row.get("ts", ""))
            return rows

        detail = self.query_packet_detail(pid)
        if not detail:
            return []
        src_ip = str(detail.get("src_ip", "") or "")
        dst_ip = str(detail.get("dst_ip", "") or "")
        src_port = int(detail.get("src_port", 0) or 0)
        dst_port = int(detail.get("dst_port", 0) or 0)
        proto = str(detail.get("proto", "") or "").upper()
        source = str(detail.get("source", "") or "")
        c = self.db.conn.cursor()
        args: list[object] = [
            proto,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            dst_ip,
            src_ip,
            dst_port,
            src_port,
        ]
        source_sql = ""
        if source:
            source_sql = " AND source=?"
            args.append(source)
        args.append(max(1, int(limit)))
        c.execute(
            f"""
            SELECT id, ts, src_ip, dst_ip, src_port, dst_port, proto, length, process_name, raw_hex, source
            FROM captured_packets
            WHERE proto=?
              AND (
                (src_ip=? AND dst_ip=? AND src_port=? AND dst_port=?)
                OR
                (src_ip=? AND dst_ip=? AND src_port=? AND dst_port=?)
              )
              {source_sql}
            ORDER BY ts ASC, id ASC
            LIMIT ?
            """,
            tuple(args),
        )
        rows = [dict(r) for r in c.fetchall()]
        for row in rows:
            row["ts_epoch"] = self._parse_ts_float(row.get("ts", 0.0))
            row["ts"] = self._render_ts_text(row.get("ts", ""))
        return rows

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
        total_file_bytes = int(os.path.getsize(pcap_path)) if pcap_path.exists() else 0
        profile = self.get_offline_import_profile(mode)
        self._offline_cpu_last_sample = 0.0
        self.clear_offline_analysis_data(clear_alerts=bool(profile.enable_detection))
        self._begin_offline_write_mode(profile)
        start_alert_id = self._current_alert_max_id()
        learning_until_backup = float(getattr(self.detector, "learning_until", 0.0))
        if self.detector.in_learning():
            self.detector.learning_until = 0.0
        self.offline_progress = {
            "running": True,
            "processed": 0,
            "alerts": 0,
            "file": str(pcap_path),
            "percent": 0.0,
            "bytes": 0,
            "total_bytes": total_file_bytes,
            "mode": profile.mode,
            "parser_threads": profile.parser_threads,
            "cpu_limit_percent": profile.cpu_limit_percent,
        }
        total_packets = 0
        total_alerts = 0
        try:
            parser_cfg = OfflineParserConfig(
                batch_size=profile.batch_size,
                raw_hex_preview_bytes=profile.raw_hex_preview_bytes,
                prefer_native=True,
                fallback_to_scapy=False,
                enable_app_meta=profile.enable_app_meta,
                worker_threads=profile.parser_threads,
            )
            for packet_batch in iter_offline_batches(pcap_path, parser_cfg):
                batch = packet_batch.packets
                alerts = self._process_offline_batch(batch, profile)
                self._apply_offline_cpu_limit(profile)
                total_packets += len(batch)
                total_alerts += alerts
                self.offline_progress["processed"] = total_packets
                self.offline_progress["alerts"] = total_alerts
                current_bytes = int(packet_batch.bytes_read or 0)
                self.offline_progress["bytes"] = current_bytes
                if total_file_bytes > 0:
                    self.offline_progress["percent"] = min(100.0, (current_bytes / total_file_bytes) * 100.0)
            total_alerts += self._flush_remaining_offline_features()
            total_alerts += self._flush_offline_feature_buffer(force=True)
            self.offline_progress["bytes"] = total_file_bytes
            self.offline_progress["percent"] = 100.0
            final_alerts = max(total_alerts, self._count_new_alerts(start_alert_id, source="offline"))
            self.offline_progress["alerts"] = final_alerts
            return total_packets, final_alerts
        except OfflineParserError as e:
            raise RuntimeError(str(e)) from e
        finally:
            self._end_offline_write_mode()
            self.detector.learning_until = learning_until_backup
            self.offline_progress["running"] = False

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
            from scapy.all import ICMP, IP, TCP, UDP, wrpcap

            packets = []
            for row in rows:
                src_ip = str(row.get("src_ip", "") or "0.0.0.0")
                dst_ip = str(row.get("dst_ip", "") or "0.0.0.0")
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

    def block_ip_with_firewall(self, ip: str, operator: str) -> tuple[bool, str]:
        target = (ip or "").strip()
        if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
            return False, "IP格式无效"
        rule_base = f"AI_Traffic_Guard_Block_{target}"
        cmds = [
            ["netsh", "advfirewall", "firewall", "add", "rule", f'name="{rule_base}_OUT"', "dir=out", "action=block", f"remoteip={target}"],
            ["netsh", "advfirewall", "firewall", "add", "rule", f'name="{rule_base}_IN"', "dir=in", "action=block", f"remoteip={target}"],
        ]
        for cmd in cmds:
            res = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if res.returncode != 0:
                msg = (res.stderr or res.stdout or "").strip() or "防火墙规则写入失败，请以管理员权限运行"
                return False, msg
        self.blocked_ips.add(target)
        self.list_service.upsert(target, "black", 1, "firewall_auto_block")
        self.audit.log(operator, "firewall_block_ip", target, "desktop_one_click")
        self.last_summary["firewall_blocks"] = len(self.blocked_ips)
        return True, "封禁成功"

    def generate_security_report(self, operator: str) -> Path:
        path = self.report_service.generate_visual_report()
        self.audit.log(operator, "report_generate", str(path), "visual_security_report")
        return path
