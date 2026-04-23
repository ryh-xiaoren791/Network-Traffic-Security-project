from collections import defaultdict
from dataclasses import dataclass
import ipaddress

import numpy as np


@dataclass
class SessionStat:
    first_ts: float
    last_ts: float
    packets: int
    total_bytes: int
    intervals: list[float]
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str
    direction: str
    process_id: int
    process_name: str
    max_pkt_size: int
    min_pkt_size: int
    syn_count: int
    ack_count: int
    fin_count: int
    rst_count: int
    syn_ack_count: int
    payload_preview: str


class SessionAggregator:
    def __init__(self) -> None:
        self.sessions: dict[str, SessionStat] = {}
        self.dirty_sessions: set[str] = set()
        self.src_port_windows = defaultdict(set)
        self.recent_sessions = defaultdict(list)
        self.internal_targets = defaultdict(set)
        self.sensitive_port_hits = defaultdict(int)

    @staticmethod
    def _key(pkt: dict) -> str:
        return f"{pkt['src_ip']}:{pkt['src_port']}->{pkt['dst_ip']}:{pkt['dst_port']}/{pkt['proto']}/{pkt['direction']}"

    def ingest_batch(self, packets: list[dict]) -> None:
        for pkt in packets:
            flags, payload_preview = self._resolve_flags_and_payload(pkt)
            key = self._key(pkt)
            now = pkt["ts"]
            pkt_len = int(pkt["length"])
            syn_count = 1 if "SYN" in flags else 0
            ack_count = 1 if "ACK" in flags else 0
            fin_count = 1 if "FIN" in flags else 0
            rst_count = 1 if "RST" in flags else 0
            syn_ack_count = 1 if ("SYN" in flags and "ACK" in flags) else 0
            if key not in self.sessions:
                self.sessions[key] = SessionStat(
                    first_ts=now,
                    last_ts=now,
                    packets=1,
                    total_bytes=pkt_len,
                    intervals=[],
                    src_ip=pkt["src_ip"],
                    dst_ip=pkt["dst_ip"],
                    src_port=int(pkt["src_port"]),
                    dst_port=int(pkt["dst_port"]),
                    proto=pkt["proto"],
                    direction=pkt["direction"],
                    process_id=int(pkt.get("process_id", 0)),
                    process_name=str(pkt.get("process_name", "")),
                    max_pkt_size=pkt_len,
                    min_pkt_size=pkt_len,
                    syn_count=syn_count,
                    ack_count=ack_count,
                    fin_count=fin_count,
                    rst_count=rst_count,
                    syn_ack_count=syn_ack_count,
                    payload_preview=payload_preview,
                )
            else:
                s = self.sessions[key]
                s.intervals.append(max(0.0, now - s.last_ts))
                s.last_ts = now
                s.packets += 1
                s.total_bytes += pkt_len
                s.max_pkt_size = max(s.max_pkt_size, pkt_len)
                s.min_pkt_size = min(s.min_pkt_size, pkt_len)
                s.syn_count += syn_count
                s.ack_count += ack_count
                s.fin_count += fin_count
                s.rst_count += rst_count
                s.syn_ack_count += syn_ack_count
                if not s.payload_preview and payload_preview:
                    s.payload_preview = payload_preview
                if not s.process_name and pkt.get("process_name"):
                    s.process_name = str(pkt.get("process_name", ""))
                    s.process_id = int(pkt.get("process_id", 0))
            self.dirty_sessions.add(key)
            src_ip = str(pkt["src_ip"])
            dst_ip = str(pkt["dst_ip"])
            dst_port = int(pkt["dst_port"])
            self.src_port_windows[src_ip].add(dst_port)
            self.recent_sessions[src_ip].append(now)
            if self._is_private_ip(dst_ip):
                self.internal_targets[src_ip].add(dst_ip)
            if self._is_sensitive_port(dst_port):
                self.sensitive_port_hits[src_ip] += 1

    @staticmethod
    def _flags_from_mask(mask: int) -> set[str]:
        v = int(mask or 0)
        flags: set[str] = set()
        if v & 0x02:
            flags.add("SYN")
        if v & 0x10:
            flags.add("ACK")
        if v & 0x01:
            flags.add("FIN")
        if v & 0x04:
            flags.add("RST")
        return flags

    def _resolve_flags_and_payload(self, pkt: dict) -> tuple[set[str], str]:
        pre_flags = pkt.get("tcp_flags_mask")
        pre_payload = str(pkt.get("payload_preview", "") or "")
        if pre_flags is not None or pre_payload:
            return self._flags_from_mask(int(pre_flags or 0)), pre_payload[:256]
        return self._extract_flags_and_payload(str(pkt.get("raw_hex", "")))

    def cleanup_expired(self, now_ts: float, timeout_sec: int = 60) -> int:
        expired = [k for k, s in self.sessions.items() if now_ts - s.last_ts > timeout_sec]
        for key in expired:
            self.sessions.pop(key, None)
            self.dirty_sessions.discard(key)
        return len(expired)

    def flush_features(self, now_ts: float, only_dirty: bool = True) -> list[dict]:
        features: list[dict] = []
        keys = list(self.dirty_sessions) if only_dirty else list(self.sessions.keys())
        for key in keys:
            s = self.sessions.get(key)
            if s is None:
                continue
            duration = max(0.001, s.last_ts - s.first_ts)
            packet_rate = s.packets / duration
            avg_pkt_size = s.total_bytes / max(1, s.packets)
            req_interval = float(np.mean(s.intervals)) if s.intervals else duration
            interval_std = float(np.std(s.intervals)) if s.intervals else 0.0
            port_visits = len(self.src_port_windows[s.src_ip])
            recent = [t for t in self.recent_sessions[s.src_ip] if now_ts - t <= 5]
            conn_freq = len(recent) / 5.0
            success_rate = 1.0 if s.syn_count <= 0 else min(1.0, (s.syn_ack_count + s.ack_count) / max(1, s.syn_count * 2))
            syn_ratio = s.syn_count / max(1, s.packets)
            src_is_private = self._is_private_ip(s.src_ip)
            dst_is_private = self._is_private_ip(s.dst_ip)
            src_is_loopback = self._is_loopback_ip(s.src_ip)
            dst_is_loopback = self._is_loopback_ip(s.dst_ip)
            dst_port_type = self._classify_port(s.dst_port)
            is_sensitive_port = self._is_sensitive_port(s.dst_port)
            features.append(
                {
                    "src_ip": s.src_ip,
                    "dst_ip": s.dst_ip,
                    "src_port": s.src_port,
                    "dst_port": s.dst_port,
                    "proto": s.proto,
                    "packet_rate": packet_rate,
                    "conn_freq": conn_freq,
                    "port_visits": port_visits,
                    "session_duration": duration,
                    "req_interval": req_interval,
                    "interval_std": interval_std,
                    "conn_success_rate": success_rate,
                    "avg_pkt_size": avg_pkt_size,
                    "max_pkt_size": s.max_pkt_size,
                    "min_pkt_size": s.min_pkt_size,
                    "total_bytes": s.total_bytes,
                    "syn_count": s.syn_count,
                    "ack_count": s.ack_count,
                    "fin_count": s.fin_count,
                    "rst_count": s.rst_count,
                    "syn_ratio": syn_ratio,
                    "src_is_private": src_is_private,
                    "dst_is_private": dst_is_private,
                    "src_is_loopback": src_is_loopback,
                    "dst_is_loopback": dst_is_loopback,
                    "dst_port_type": dst_port_type,
                    "is_sensitive_port": is_sensitive_port,
                    "internal_target_count": len(self.internal_targets[s.src_ip]),
                    "sensitive_port_hits": self.sensitive_port_hits[s.src_ip],
                    "payload_preview": s.payload_preview,
                    "direction": s.direction,
                    "process_id": s.process_id,
                    "process_name": s.process_name,
                }
            )
        if only_dirty:
            self.dirty_sessions.clear()
        return features

    @staticmethod
    def _extract_flags_and_payload(raw_hex: str) -> tuple[set[str], str]:
        if not raw_hex:
            return set(), ""
        try:
            from scapy.all import IP, IPv6, Raw, TCP
        except Exception:
            return set(), ""
        try:
            raw_bytes = bytes.fromhex(raw_hex)
        except Exception:
            return set(), ""
        pkt = None
        try:
            pkt = IP(raw_bytes)
        except Exception:
            try:
                pkt = IPv6(raw_bytes)
            except Exception:
                pkt = None
        if pkt is None:
            return set(), ""
        flags: set[str] = set()
        if pkt.haslayer(TCP):
            tcp_layer = pkt[TCP]
            if tcp_layer.flags & 0x02:
                flags.add("SYN")
            if tcp_layer.flags & 0x10:
                flags.add("ACK")
            if tcp_layer.flags & 0x01:
                flags.add("FIN")
            if tcp_layer.flags & 0x04:
                flags.add("RST")
        payload_preview = ""
        if pkt.haslayer(Raw):
            payload_preview = bytes(pkt[Raw]).decode("utf-8", errors="ignore").lower()[:256]
        return flags, payload_preview

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).is_private
        except Exception:
            return False

    @staticmethod
    def _is_loopback_ip(ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).is_loopback
        except Exception:
            return False

    @staticmethod
    def _classify_port(port: int) -> str:
        p = int(port or 0)
        if 0 < p <= 1023:
            return "well_known"
        if 1024 <= p <= 49151:
            return "registered"
        return "dynamic"

    @staticmethod
    def _is_sensitive_port(port: int) -> bool:
        return int(port or 0) in {21, 22, 23, 25, 53, 110, 135, 139, 143, 389, 445, 1433, 1521, 3306, 3389, 5432, 6379, 8080, 27017}
