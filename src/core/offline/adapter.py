from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
import time


LEGACY_PACKET_FIELDS = (
    "ts",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "proto",
    "length",
    "direction",
    "process_id",
    "process_name",
    "raw_hex",
)


class OfflineParserError(RuntimeError):
    pass


@dataclass(frozen=True)
class OfflineParserConfig:
    batch_size: int = 1000
    raw_hex_preview_bytes: int = 512
    prefer_native: bool = True
    fallback_to_scapy: bool = False
    enable_app_meta: bool = True
    worker_threads: int = 1


@dataclass(frozen=True)
class OfflineBatch:
    packets: Sequence[Mapping[str, object]]
    bytes_read: int


@dataclass(frozen=True)
class OfflineFrameBatch:
    frames: Sequence[Mapping[str, object]]
    bytes_read: int


@dataclass(frozen=True)
class _WrappedEthernetMeta:
    sec: int
    usec: int
    caplen: int
    wirelen: int
    linktype: int = 1


@dataclass
class _WrappedEthernetReaderState:
    bytes_read: int = 0
    linktype: int = 1


class _LegacyPacketRow(Mapping[str, object]):
    def __init__(self, columns: dict[str, Sequence[object]], row_index: int) -> None:
        self._columns = columns
        self._row_index = row_index

    def __getitem__(self, key: str) -> object:
        col = self._columns.get(key)
        if col is None:
            raise KeyError(key)
        return col[self._row_index]

    def __iter__(self):
        return iter(self._columns.keys())

    def __len__(self) -> int:
        return len(self._columns)

    def get(self, key: str, default=None):
        col = self._columns.get(key)
        if col is None:
            return default
        return col[self._row_index]


class LegacyPacketBatchView(Sequence[Mapping[str, object]]):
    """
    在 Python 侧保持“像 list[dict] 一样可读”的访问方式，底层按列存储。
    这样在 traffic_core 可用时可以避免预先构造大量 dict。
    """

    def __init__(self, columns: dict[str, Sequence[object]], row_count: int) -> None:
        self._columns = columns
        self._row_count = row_count

    def __getitem__(self, index: int) -> Mapping[str, object]:
        if not 0 <= index < self._row_count:
            raise IndexError(index)
        return _LegacyPacketRow(self._columns, index)

    def __len__(self) -> int:
        return self._row_count

    def iter_rows(self) -> Iterator[Mapping[str, object]]:
        for idx in range(self._row_count):
            yield _LegacyPacketRow(self._columns, idx)

    @property
    def row_count(self) -> int:
        return self._row_count

    def get_column(self, name: str) -> Sequence[object] | None:
        return self._columns.get(name)


def _to_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore")
    return str(value)


def _to_int(value: object) -> int:
    try:
        return int(value or 0)
    except Exception:
        return 0


def _to_float(value: object) -> float:
    try:
        return float(value or 0.0)
    except Exception:
        return 0.0


def _native_batch_to_legacy_columns(native_batch: object, raw_hex_preview_bytes: int) -> tuple[dict[str, Sequence[object]], int]:
    """
    兼容 traffic_core 的列式批量输出（dict[str, sequence]）。
    """
    if not isinstance(native_batch, dict):
        raise OfflineParserError("traffic_core批次格式无效，期望dict列式结构")
    columns: dict[str, Sequence[object]] = {}
    row_count = 0
    for key, value in native_batch.items():
        if str(key).startswith("_"):
            continue
        if isinstance(value, Sequence):
            columns[str(key)] = value
            try:
                row_count = max(row_count, len(value))
            except Exception:
                continue
    for field in LEGACY_PACKET_FIELDS:
        col = native_batch.get(field)
        if col is None:
            continue
        columns[field] = col
        try:
            row_count = max(row_count, len(col))
        except Exception:
            continue
    if row_count <= 0:
        return {}, 0
    # 确保兼容字段存在，不存在则补默认值列
    for field in LEGACY_PACKET_FIELDS:
        if field in columns:
            continue
        if field in {"ts"}:
            columns[field] = [0.0] * row_count
        elif field in {"src_port", "dst_port", "length", "process_id"}:
            columns[field] = [0] * row_count
        else:
            columns[field] = [""] * row_count
    # raw_hex长度限制保持与历史路径一致
    raw_col = columns.get("raw_hex")
    if raw_col is not None:
        max_hex = raw_hex_preview_bytes * 2
        columns["raw_hex"] = [_to_text(v)[:max_hex] for v in raw_col]
    return columns, row_count


def _iter_native_batches(pcap_path: Path, cfg: OfflineParserConfig) -> Iterator[OfflineBatch]:
    try:
        import traffic_core  # type: ignore
    except Exception as e:
        raise OfflineParserError(f"traffic_core不可用: {e}") from e
    if not hasattr(traffic_core, "iter_pcap_batches"):
        raise OfflineParserError("traffic_core缺少iter_pcap_batches接口")
    try:
        try:
            native_iter = traffic_core.iter_pcap_batches(
                str(pcap_path),
                int(cfg.batch_size),
                int(cfg.raw_hex_preview_bytes),
                bool(cfg.enable_app_meta),
                max(1, int(cfg.worker_threads)),
            )
        except TypeError:
            # 向后兼容旧版traffic_core（无worker_threads参数）
            native_iter = traffic_core.iter_pcap_batches(
                str(pcap_path),
                int(cfg.batch_size),
                int(cfg.raw_hex_preview_bytes),
                bool(cfg.enable_app_meta),
            )
    except Exception as e:
        raise OfflineParserError(f"traffic_core启动失败: {e}") from e
    for native_batch in native_iter:
        columns, row_count = _native_batch_to_legacy_columns(native_batch, cfg.raw_hex_preview_bytes)
        if row_count <= 0:
            continue
        bytes_read = _to_int(native_batch.get("_bytes_read", 0)) if isinstance(native_batch, dict) else 0
        yield OfflineBatch(packets=LegacyPacketBatchView(columns, row_count), bytes_read=bytes_read)


def _iter_scapy_batches(pcap_path: Path, cfg: OfflineParserConfig) -> Iterator[OfflineBatch]:
    try:
        from scapy.layers.dns import DNS, DNSRR
        from scapy.layers.inet import ICMP, IP, TCP, UDP
        from scapy.layers.inet6 import IPv6
        from scapy.layers.l2 import Ether
        from scapy.packet import Raw
        from scapy.utils import PcapReader
    except Exception as e:
        raise OfflineParserError(f"离线分析依赖Scapy不可用: {e}") from e
    def build_row(pkt: object, raw_bytes: bytes, ts: float) -> dict[str, object] | None:
        ip_layer = None
        if pkt.haslayer(IP):
            ip_layer = pkt[IP]
        elif pkt.haslayer(IPv6):
            ip_layer = pkt[IPv6]
        if not ip_layer:
            return None
        proto = "OTHER"
        src_port = 0
        dst_port = 0
        if pkt.haslayer(TCP):
            proto = "TCP"
            src_port = _to_int(pkt[TCP].sport)
            dst_port = _to_int(pkt[TCP].dport)
        elif pkt.haslayer(UDP):
            proto = "UDP"
            src_port = _to_int(pkt[UDP].sport)
            dst_port = _to_int(pkt[UDP].dport)
        elif pkt.haslayer(ICMP):
            proto = "ICMP"
        if proto not in {"TCP", "UDP", "ICMP"}:
            return None
        payload_preview = ""
        tcp_flags_mask = 0
        http_method = ""
        http_url = ""
        http_host = ""
        http_status = 0
        dns_query = ""
        dns_qtype = 0
        dns_answer = ""
        tls_sni = ""
        tls_cipher = ""
        ip_version = 4 if pkt.haslayer(IP) else 6
        ip_ttl = _to_int(getattr(ip_layer, "ttl", getattr(ip_layer, "hlim", 0)))
        ip_frag_offset = _to_int(getattr(ip_layer, "frag", 0))
        ip_more_frag = 1 if (_to_int(getattr(ip_layer, "flags", 0)) & 0x1) else 0
        if pkt.haslayer(TCP):
            tcp_flags_mask = _to_int(getattr(pkt[TCP], "flags", 0))
        if pkt.haslayer(Raw):
            payload_bytes = bytes(pkt[Raw])
            payload_preview = payload_bytes.decode("utf-8", errors="ignore").lower()[:256]
            head = payload_bytes[:1024]
            try:
                text = head.decode("latin-1", errors="ignore")
            except Exception:
                text = ""
            if proto == "TCP":
                if text.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ")):
                    first = text.split("\r\n", 1)[0]
                    parts = first.split(" ")
                    if len(parts) >= 2:
                        http_method = parts[0][:16]
                        http_url = parts[1][:512]
                    for line in text.split("\r\n"):
                        if line.lower().startswith("host:"):
                            http_host = line.split(":", 1)[1].strip()[:255]
                            break
                elif text.startswith("HTTP/"):
                    first = text.split("\r\n", 1)[0]
                    parts = first.split(" ")
                    if len(parts) >= 2:
                        http_status = _to_int(parts[1])
                if len(payload_bytes) >= 11 and payload_bytes[0] == 0x16 and payload_bytes[1] == 0x03 and payload_bytes[5] == 0x01:
                    tls_cipher = "tls_handshake"
        if pkt.haslayer(DNS):
            dns = pkt[DNS]
            try:
                if getattr(dns, "qd", None):
                    q = dns.qd
                    dns_query = _to_text(getattr(q, "qname", b"")).rstrip(".")
                    dns_qtype = _to_int(getattr(q, "qtype", 0))
                if _to_int(getattr(dns, "ancount", 0)) > 0 and getattr(dns, "an", None):
                    ans = dns.an
                    if isinstance(ans, DNSRR):
                        dns_answer = _to_text(getattr(ans, "rdata", ""))
            except Exception:
                dns_query = dns_query or ""
        return {
            "ts": _to_float(ts),
            "src_ip": _to_text(getattr(ip_layer, "src", "")),
            "dst_ip": _to_text(getattr(ip_layer, "dst", "")),
            "src_port": src_port,
            "dst_port": dst_port,
            "proto": proto,
            "length": len(raw_bytes),
            "direction": "offline",
            "process_id": 0,
            "process_name": "offline",
            "raw_hex": raw_bytes[: cfg.raw_hex_preview_bytes].hex(),
            "tcp_flags_mask": tcp_flags_mask,
            "payload_preview": payload_preview,
            "http_method": http_method,
            "http_url": http_url,
            "http_host": http_host,
            "http_status": http_status,
            "dns_query": dns_query,
            "dns_qtype": dns_qtype,
            "dns_answer": dns_answer,
            "tls_sni": tls_sni,
            "tls_cipher": tls_cipher,
            "ip_version": ip_version,
            "ip_ttl": ip_ttl,
            "ip_frag_offset": ip_frag_offset,
            "ip_more_frag": ip_more_frag,
        }

    def iter_scapy_packets() -> Iterator[tuple[object, bytes, float, int]]:
        try:
            with PcapReader(str(pcap_path)) as reader:
                for pkt in reader:
                    yield pkt, bytes(pkt), _to_float(getattr(pkt, "time", time.time())), _read_progress(reader)
                return
        except Exception as scapy_error:
            last_error = scapy_error
        if not _looks_like_wrapped_ethernet_capture(pcap_path):
            raise OfflineParserError(f"无法读取抓包文件: {last_error}")
        for raw_bytes, meta, reader in _iter_wrapped_ethernet_frames(pcap_path):
            try:
                pkt = Ether(raw_bytes)
            except Exception:
                continue
            yield pkt, raw_bytes, _metadata_timestamp(meta), _read_progress(reader)

    batch: list[dict[str, object]] = []
    bytes_read = 0
    for pkt, raw_bytes, ts, bytes_read in iter_scapy_packets():
        row = build_row(pkt, raw_bytes, ts)
        if row is None:
            continue
        batch.append(row)
        if len(batch) >= cfg.batch_size:
            yield OfflineBatch(packets=batch, bytes_read=bytes_read)
            batch = []
    if batch:
        yield OfflineBatch(packets=batch, bytes_read=bytes_read)


def _pcapng_timestamp_seconds(meta: object) -> float:
    try:
        ts_high = int(getattr(meta, "tshigh", 0) or 0)
        ts_low = int(getattr(meta, "tslow", 0) or 0)
        ts_resol = int(getattr(meta, "tsresol", 1_000_000) or 1_000_000)
        combined = (ts_high << 32) | ts_low
        if ts_resol <= 0:
            ts_resol = 1_000_000
        return float(combined) / float(ts_resol)
    except Exception:
        return 0.0


def _metadata_timestamp(meta: object) -> float:
    sec = getattr(meta, "sec", None)
    usec = getattr(meta, "usec", None)
    if sec is not None:
        try:
            return float(sec) + (float(usec or 0) / 1_000_000.0)
        except Exception:
            pass
    ts = _pcapng_timestamp_seconds(meta)
    if ts > 0:
        return ts
    return time.time()


def _read_progress(reader: object) -> int:
    try:
        bytes_read = int(getattr(reader, "bytes_read", 0) or 0)
        if bytes_read > 0:
            return bytes_read
    except Exception:
        pass
    try:
        return int(getattr(getattr(reader, "f", None), "tell", lambda: 0)() or 0)
    except Exception:
        return 0


def _linktype_name(linktype: int) -> str:
    mapping = {
        0: "unknown",
        1: "ethernet",
        12: "loopback",
        101: "raw-ip",
        113: "linux-sll",
        127: "radiotap",
        220: "usb-linux",
        249: "linktype-249",
    }
    return mapping.get(int(linktype or 0), f"linktype-{int(linktype or 0)}")


def _build_frame_summary(raw_bytes: bytes, linktype: int) -> str:
    link_name = _linktype_name(linktype)
    ascii_preview = "".join(chr(b) if 32 <= b <= 126 else "." for b in raw_bytes[:32]).strip(".")
    if linktype == 1 and len(raw_bytes) >= 14:
        ether_type = int.from_bytes(raw_bytes[12:14], "big")
        return f"{link_name} ethertype=0x{ether_type:04x} len={len(raw_bytes)}"
    if ascii_preview:
        return f"{link_name} len={len(raw_bytes)} ascii={ascii_preview[:24]}"
    return f"{link_name} len={len(raw_bytes)}"


def _looks_like_wrapped_ethernet_capture(pcap_path: Path) -> bool:
    try:
        header = pcap_path.read_bytes()[:56]
    except Exception:
        return False
    if len(header) < 56:
        return False
    if not header.startswith(bytes.fromhex("aaaaaaaa200000000000010018000000")):
        return False
    return header[32:40] == bytes.fromhex("0700008004000100")


def _iter_wrapped_ethernet_frames(pcap_path: Path) -> Iterator[tuple[bytes, object, object]]:
    data = pcap_path.read_bytes()
    if len(data) < 92 or not _looks_like_wrapped_ethernet_capture(pcap_path):
        raise OfflineParserError("不是已知的封装以太网抓包格式")
    reader = _WrappedEthernetReaderState()
    offset = 56
    total = len(data)
    while offset + 36 <= total:
        header = data[offset : offset + 36]
        if len(header) < 36:
            break
        if header[:16] != bytes.fromhex("eeee3333240000400000008000000000"):
            break
        caplen = int.from_bytes(header[16:20], "little")
        sec = int.from_bytes(header[24:28], "little")
        usec = int.from_bytes(header[28:32], "little")
        if caplen <= 0:
            break
        frame_start = offset + 36
        frame_end = frame_start + caplen
        if frame_end > total:
            break
        raw_bytes = data[frame_start:frame_end]
        meta = _WrappedEthernetMeta(sec=sec, usec=usec, caplen=caplen, wirelen=caplen, linktype=1)
        reader.bytes_read = frame_end
        yield raw_bytes, meta, reader
        offset = frame_end


def _iter_raw_frames(pcap_path: Path) -> Iterator[tuple[bytes, object, object]]:
    try:
        from scapy.utils import RawPcapNgReader, RawPcapReader
    except Exception as e:
        raise OfflineParserError(f"离线原始帧读取依赖Scapy不可用: {e}") from e

    if _looks_like_wrapped_ethernet_capture(pcap_path):
        yield from _iter_wrapped_ethernet_frames(pcap_path)
        return

    suffix = pcap_path.suffix.lower()
    readers = [RawPcapNgReader, RawPcapReader] if suffix == ".pcapng" else [RawPcapReader, RawPcapNgReader]
    last_error: Exception | None = None
    for reader_cls in readers:
        reader = None
        try:
            reader = reader_cls(str(pcap_path))
            for raw_bytes, meta in reader:
                yield raw_bytes, meta, reader
            return
        except Exception as e:
            last_error = e
        finally:
            try:
                if reader is not None:
                    reader.close()
            except Exception:
                pass
    raise OfflineParserError(f"无法读取抓包文件: {last_error}")


def iter_offline_generic_frames(pcap_path: Path, cfg: OfflineParserConfig) -> Iterator[OfflineFrameBatch]:
    batch: list[dict[str, object]] = []
    frame_no = 0
    for raw_bytes, meta, reader in _iter_raw_frames(pcap_path):
        frame_no += 1
        linktype = int(getattr(meta, "linktype", getattr(reader, "linktype", 0)) or 0)
        iface_name = _to_text(getattr(meta, "ifname", b""))
        frame = {
            "frame_no": frame_no,
            "ts": _metadata_timestamp(meta),
            "linktype": linktype,
            "iface": iface_name[:180],
            "frame_type": _linktype_name(linktype),
            "caplen": _to_int(getattr(meta, "caplen", len(raw_bytes))),
            "wirelen": _to_int(getattr(meta, "wirelen", len(raw_bytes))),
            "summary": _build_frame_summary(raw_bytes, linktype),
            "raw_hex": raw_bytes[: cfg.raw_hex_preview_bytes].hex(),
        }
        batch.append(frame)
        if len(batch) >= cfg.batch_size:
            yield OfflineFrameBatch(frames=batch, bytes_read=_read_progress(reader))
            batch = []
    if batch:
        yield OfflineFrameBatch(frames=batch, bytes_read=0)


def iter_offline_batches(pcap_path: Path, cfg: OfflineParserConfig) -> Iterator[OfflineBatch]:
    """
    统一离线包源：
    1) 优先使用 traffic_core（C++/pybind11）；
    2) 不可用时自动回退 Scapy，保持字段兼容。
    """
    if cfg.prefer_native:
        try:
            yield from _iter_native_batches(pcap_path, cfg)
            return
        except OfflineParserError:
            if not cfg.fallback_to_scapy:
                raise
    yield from _iter_scapy_batches(pcap_path, cfg)
