import ipaddress
import platform
import queue
import socket
import subprocess
import threading
import time
from dataclasses import dataclass

import psutil


@dataclass
class CaptureConfig:
    interface: str
    capture_outbound: bool


class CaptureEngine:
    def __init__(self, packet_queue: queue.Queue) -> None:
        self.packet_queue = packet_queue
        self.running = False
        self.thread: threading.Thread | None = None
        self.config: CaptureConfig | None = None
        self.capture_loopback = False
        self.interface_ip = ""
        self.interface_ips: set[str] = set()
        self.interface_networks: list[ipaddress.IPv4Network] = []
        self.interface_index = 0
        self._conn_cache: dict[tuple[str, str, int, str, int], tuple[int, str]] = {}
        self._conn_cache_ts = 0.0
        self._divert = None

    @staticmethod
    def _safe_close_divert(divert) -> None:
        if divert is None:
            return
        try:
            if getattr(divert, "is_open", False):
                divert.close()
        except Exception:
            return

    @staticmethod
    def list_interfaces() -> list[dict]:
        addrs = psutil.net_if_addrs()
        out: list[dict] = []
        out.append({"name": "__loopback__", "display_name": "Loopback [Loopback] (127.0.0.1)"})
        for name, rows in addrs.items():
            ipv4 = ""
            for row in rows:
                if row.family == socket.AF_INET and row.address and not str(row.address).startswith("127."):
                    ipv4 = str(row.address)
                    break
            if not ipv4:
                continue
            low = name.lower()
            tag = "VMware" if "vmware" in low else "Virtual" if "virtual" in low or "vbox" in low or "hyper-v" in low else "Physical"
            shown = f"{name} [{tag}] ({ipv4})"
            out.append({"name": name, "display_name": shown})
        if out:
            return out
        return [{"name": n, "display_name": n} for n in addrs.keys()]

    @staticmethod
    def _interface_ips_by_name(interface_name: str) -> set[str]:
        rows = psutil.net_if_addrs().get(interface_name, [])
        ips: set[str] = set()
        for row in rows:
            if row.family == socket.AF_INET and row.address and not str(row.address).startswith("127."):
                ip = str(row.address)
                try:
                    parsed = ipaddress.ip_address(ip)
                    if parsed.is_link_local:
                        continue
                except ValueError:
                    continue
                ips.add(ip)
        return ips

    @staticmethod
    def _interface_networks_by_name(interface_name: str) -> list[ipaddress.IPv4Network]:
        rows = psutil.net_if_addrs().get(interface_name, [])
        networks: list[ipaddress.IPv4Network] = []
        for row in rows:
            if row.family != socket.AF_INET or not row.address or str(row.address).startswith("127."):
                continue
            if not row.netmask:
                continue
            try:
                net = ipaddress.ip_network(f"{row.address}/{row.netmask}", strict=False)
            except ValueError:
                continue
            if isinstance(net, ipaddress.IPv4Network):
                networks.append(net)
        if not networks:
            ips = CaptureEngine._interface_ips_by_name(interface_name)
            for ip in ips:
                parts = ip.split(".")
                if len(parts) != 4:
                    continue
                try:
                    networks.append(ipaddress.ip_network(f"{parts[0]}.{parts[1]}.{parts[2]}.0/24", strict=False))
                except ValueError:
                    continue
        return networks

    def _normalize(self, pkt) -> dict | None:
        src_ip = str(getattr(pkt, "src_addr", "") or "")
        dst_ip = str(getattr(pkt, "dst_addr", "") or "")
        pkt_bytes = getattr(pkt, "raw", b"")
        proto, scapy_src_port, scapy_dst_port, scapy_src_ip, scapy_dst_ip = self._parse_with_scapy(pkt_bytes)
        scapy_matched = proto in {"TCP", "UDP", "ICMP"}
        if scapy_matched and scapy_src_ip:
            src_ip = scapy_src_ip
        if scapy_matched and scapy_dst_ip:
            dst_ip = scapy_dst_ip
        if proto == "OTHER":
            proto_no = self._extract_proto_no(pkt)
            proto = "TCP" if proto_no == 6 else "UDP" if proto_no == 17 else "ICMP" if proto_no in {1, 58} else "OTHER"
        if proto not in {"TCP", "UDP", "ICMP"}:
            return None
        try:
            sip = ipaddress.ip_address(src_ip)
            dip = ipaddress.ip_address(dst_ip)
            is_loop = sip.is_loopback or dip.is_loopback
            if self.capture_loopback:
                if not is_loop:
                    return None
            elif is_loop:
                return None
            if dip.is_multicast:
                return None
            if dst_ip.endswith(".255"):
                return None
        except ValueError:
            return None
        if not self.capture_loopback:
            if self.interface_networks:
                if not any(sip in net or dip in net for net in self.interface_networks):
                    return None
            elif self.interface_ips:
                if src_ip not in self.interface_ips and dst_ip not in self.interface_ips:
                    return None
        direction = "inbound" if bool(getattr(pkt, "is_inbound", False)) else "outbound" if bool(getattr(pkt, "is_outbound", False)) else "inbound"
        if self.capture_loopback:
            direction = "inbound"
        elif self.interface_ip and src_ip == self.interface_ip:
            direction = "outbound"
        if direction == "outbound" and proto != "ICMP" and self.config and not self.config.capture_outbound:
            return None
        src_port = int(scapy_src_port if scapy_matched and scapy_src_port > 0 else (getattr(pkt, "src_port", 0) or 0))
        dst_port = int(scapy_dst_port if scapy_matched and scapy_dst_port > 0 else (getattr(pkt, "dst_port", 0) or 0))
        process_id, process_name = self._lookup_process(proto, src_ip, src_port, dst_ip, dst_port, direction)
        length = len(pkt_bytes) if isinstance(pkt_bytes, (bytes, bytearray)) else int(getattr(pkt, "payload_length", 0) or 0)
        return {
            "ts": time.time(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "proto": proto,
            "length": int(length),
            "direction": direction,
            "process_id": process_id,
            "process_name": process_name,
            "raw_hex": pkt_bytes[:512].hex() if isinstance(pkt_bytes, (bytes, bytearray)) else "",
        }

    @staticmethod
    def _parse_with_scapy(pkt_bytes: bytes) -> tuple[str, int, int, str, str]:
        if not isinstance(pkt_bytes, (bytes, bytearray)) or not pkt_bytes:
            return "OTHER", 0, 0, "", ""
        try:
            from scapy.all import ICMP, IP, IPv6, TCP, UDP
        except Exception:
            return "OTHER", 0, 0, "", ""
        src_ip = ""
        dst_ip = ""
        src_port = 0
        dst_port = 0
        try:
            ip_pkt = IP(pkt_bytes)
        except Exception:
            try:
                ip_pkt = IPv6(pkt_bytes)
            except Exception:
                return "OTHER", 0, 0, "", ""
        src_ip = str(getattr(ip_pkt, "src", "") or "")
        dst_ip = str(getattr(ip_pkt, "dst", "") or "")
        if ip_pkt.haslayer(TCP):
            layer = ip_pkt[TCP]
            src_port = int(getattr(layer, "sport", 0) or 0)
            dst_port = int(getattr(layer, "dport", 0) or 0)
            return "TCP", src_port, dst_port, src_ip, dst_ip
        if ip_pkt.haslayer(UDP):
            layer = ip_pkt[UDP]
            src_port = int(getattr(layer, "sport", 0) or 0)
            dst_port = int(getattr(layer, "dport", 0) or 0)
            return "UDP", src_port, dst_port, src_ip, dst_ip
        if ip_pkt.haslayer(ICMP):
            return "ICMP", 0, 0, src_ip, dst_ip
        try:
            proto_no = int(getattr(ip_pkt, "proto", 0) or 0)
        except Exception:
            proto_no = 0
        if proto_no == 58:
            return "ICMP", 0, 0, src_ip, dst_ip
        return "OTHER", src_port, dst_port, src_ip, dst_ip

    @staticmethod
    def _extract_proto_no(pkt) -> int:
        v = getattr(pkt, "protocol", 0)
        if isinstance(v, tuple):
            first = v[0] if v else 0
            try:
                return int(first or 0)
            except Exception:
                return 0
        try:
            return int(v or 0)
        except Exception:
            return 0

    def _lookup_process(
        self, proto: str, src_ip: str, src_port: int, dst_ip: str, dst_port: int, direction: str
    ) -> tuple[int, str]:
        if proto not in {"TCP", "UDP"}:
            return 0, ""
        self._refresh_connection_cache()
        if direction == "outbound":
            key = (proto, src_ip, src_port, dst_ip, dst_port)
        else:
            key = (proto, dst_ip, dst_port, src_ip, src_port)
        return self._conn_cache.get(key, (0, ""))

    def _refresh_connection_cache(self) -> None:
        now = time.time()
        if now - self._conn_cache_ts < 1.0:
            return
        try:
            import psutil
        except Exception:
            self._conn_cache_ts = now
            return
        proto_map = {
            socket.SOCK_STREAM: "TCP",
            socket.SOCK_DGRAM: "UDP",
        }
        cache: dict[tuple[str, str, int, str, int], tuple[int, str]] = {}
        try:
            conns = psutil.net_connections(kind="inet")
            for c in conns:
                proto = proto_map.get(c.type)
                if not proto:
                    continue
                if not c.laddr or not c.raddr:
                    continue
                laddr = c.laddr
                raddr = c.raddr
                pid = int(c.pid or 0)
                pname = ""
                if pid > 0:
                    try:
                        pname = psutil.Process(pid).name()
                    except Exception:
                        pname = ""
                key = (proto, str(laddr.ip), int(laddr.port), str(raddr.ip), int(raddr.port))
                cache[key] = (pid, pname)
        except Exception:
            pass
        self._conn_cache = cache
        self._conn_cache_ts = now

    def _sniff_loop(self) -> None:
        assert self.config is not None
        try:
            import pydivert
        except Exception:
            self.running = False
            return
        filter_text = "ip and (tcp or udp or icmp)"
        wd = None
        try:
            flag_cls = getattr(pydivert, "Flag", None)
            if flag_cls is not None and hasattr(flag_cls, "SNIFF"):
                wd = pydivert.WinDivert(filter_text, flags=flag_cls.SNIFF)
            else:
                wd = pydivert.WinDivert(filter_text)
        except Exception:
            wd = pydivert.WinDivert(filter_text)
        divert = wd
        try:
            divert.open()
            self._divert = divert
            while self.running:
                try:
                    pkt = divert.recv()
                except Exception:
                    if not self.running:
                        break
                    time.sleep(0.02)
                    continue
                try:
                    item = self._normalize(pkt)
                except Exception:
                    continue
                if not item:
                    continue
                try:
                    self.packet_queue.put_nowait(item)
                except queue.Full:
                    continue
        finally:
            self._safe_close_divert(divert)
            if self._divert is divert:
                self._divert = None

    def start(self, interface: str, capture_outbound: bool = False) -> None:
        self.stop()
        self.config = CaptureConfig(interface=interface, capture_outbound=capture_outbound)
        self.capture_loopback = interface == "__loopback__"
        if self.capture_loopback:
            self.interface_ips = {"127.0.0.1"}
            self.interface_networks = []
            self.interface_ip = "127.0.0.1"
            self.interface_index = 1
        else:
            self.interface_ips = self._interface_ips_by_name(interface)
            self.interface_networks = self._interface_networks_by_name(interface)
            self.interface_ip = next(iter(self.interface_ips), "")
            try:
                self.interface_index = socket.if_nametoindex(interface)
            except Exception:
                self.interface_index = 0
        self.running = True
        self.thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.running = False
        self.capture_loopback = False
        self.interface_networks = []
        self.interface_index = 0
        divert = self._divert
        self._divert = None
        self._safe_close_divert(divert)

    @staticmethod
    def set_interface_enabled(interface_name: str, enabled: bool) -> tuple[bool, str]:
        name = (interface_name or "").strip()
        if not name:
            return False, "网卡名称为空"
        if platform.system().lower() != "windows":
            return False, "仅支持Windows系统"
        state = "enabled" if enabled else "disabled"
        try:
            result = subprocess.run(
                ["netsh", "interface", "set", "interface", f'name="{name}"', f"admin={state}"],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode == 0:
                return True, "操作成功"
            msg = (result.stderr or result.stdout or "").strip()
            if not msg:
                msg = "操作失败，请以管理员权限运行"
            return False, msg
        except Exception as e:
            return False, str(e)
