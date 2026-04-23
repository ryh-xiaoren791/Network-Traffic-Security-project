from dataclasses import dataclass
import re


@dataclass
class Baseline:
    packet_rate_mean: float = 20.0
    packet_rate_std: float = 10.0
    conn_freq_mean: float = 5.0
    conn_freq_std: float = 2.0


class RuleEngine:
    def __init__(self) -> None:
        self.baseline = Baseline()

    def update_baseline(self, packet_rate_mean: float, packet_rate_std: float, conn_freq_mean: float, conn_freq_std: float) -> None:
        self.baseline = Baseline(packet_rate_mean, packet_rate_std, conn_freq_mean, conn_freq_std)

    def detect(self, f: dict, role_violation: bool = False) -> dict:
        reasons: list[str] = []
        category = "访问与流量类"
        sub = "正常"
        level = "low"
        is_loopback_pair = str(f.get("src_ip", "")).startswith("127.") and str(f.get("dst_ip", "")).startswith("127.")

        pkt_rate = float(f.get("packet_rate", 0.0))
        conn_freq = float(f.get("conn_freq", 0.0))
        dst_port = int(f.get("dst_port", 0) or 0)
        proto = str(f.get("proto", "")).upper()
        session_duration = float(f.get("session_duration", 0.0))
        req_interval = float(f.get("req_interval", 0.0))
        interval_std = float(f.get("interval_std", 0.0))
        avg_pkt_size = float(f.get("avg_pkt_size", 0.0))
        total_bytes = float(f.get("total_bytes", f.get("avg_pkt_size", 0.0)))
        dst_port_type = str(f.get("dst_port_type", ""))
        direction = str(f.get("direction", ""))
        payload_preview = str(f.get("payload_preview", "")).lower()
        syn_ratio = float(f.get("syn_ratio", 0.0))
        conn_success_rate = float(f.get("conn_success_rate", 1.0))
        is_sensitive_port = bool(f.get("is_sensitive_port", False))
        src_is_private = bool(f.get("src_is_private", False))
        dst_is_private = bool(f.get("dst_is_private", False))
        internal_target_count = int(f.get("internal_target_count", 0) or 0)
        sensitive_port_hits = int(f.get("sensitive_port_hits", 0) or 0)

        pkt_th = self.baseline.packet_rate_mean + 3 * max(1.0, self.baseline.packet_rate_std)
        conn_th = self.baseline.conn_freq_mean + 3 * max(0.5, self.baseline.conn_freq_std)
        flood_th = max(pkt_th, 120.0)
        brute_th = max(conn_th, 12.0)
        scan_th = max(conn_th, 8.0)
        large_bytes_th = max(1_500_000.0, self.baseline.packet_rate_mean * 40000.0)

        def apply(cat: str, sub_cat: str, lv: str, reason: str) -> None:
            nonlocal category, sub, level
            rank = {"low": 1, "medium": 2, "high": 3}
            reasons.append(reason)
            if rank.get(lv, 1) >= rank.get(level, 1):
                category, sub, level = cat, sub_cat, lv

        if proto == "TCP" and syn_ratio > 0.5 and pkt_rate > flood_th:
            apply("拒绝服务攻击类", "SYN Flood攻击", "high", f"SYN比例{syn_ratio:.2f}且包频率{pkt_rate:.2f}异常")
        if proto == "UDP" and pkt_rate > flood_th:
            apply("拒绝服务攻击类", "UDP Flood攻击", "high", f"UDP包频率{pkt_rate:.2f}超阈值")
        if proto == "ICMP" and pkt_rate > flood_th:
            apply("拒绝服务攻击类", "ICMP Flood攻击", "high", f"ICMP包频率{pkt_rate:.2f}超阈值")

        if dst_port == 22 and conn_freq > brute_th:
            apply("暴力破解类", "SSH暴力破解", "high", f"SSH连接频率{conn_freq:.2f}异常")
        if dst_port == 3389 and conn_freq > brute_th:
            apply("暴力破解类", "RDP暴力破解", "high", f"RDP连接频率{conn_freq:.2f}异常")
        if dst_port in {3306, 5432, 6379, 27017} and conn_freq > brute_th:
            apply("暴力破解类", "数据库暴力破解", "high", f"数据库端口{dst_port}连接频率异常")
        if dst_port == 21 and conn_freq > brute_th:
            apply("暴力破解类", "FTP暴力破解", "medium", f"FTP连接频率{conn_freq:.2f}异常")
        if dst_port in {80, 443, 8080} and conn_freq > brute_th and conn_success_rate < 0.3:
            apply("暴力破解类", "Web暴力破解", "medium", f"Web连接频率{conn_freq:.2f}且成功率{conn_success_rate:.2f}")

        if internal_target_count > 10 and conn_freq > scan_th:
            apply("横向移动类", "内网扫描行为", "high", f"访问内网目标{internal_target_count}个")
        if f.get("port_visits", 0) >= 30:
            apply("端口与服务类", "端口扫描行为", "high", f"5秒内访问端口数{f.get('port_visits', 0)}触发端口扫描")
        common_service_ports = {21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389}
        if dst_port in common_service_ports and conn_freq > scan_th:
            apply("端口与服务类", "服务探测行为", "medium", f"常见服务端口{dst_port}访问频率异常")

        if direction == "outbound" and dst_port > 10000 and session_duration > 60 and pkt_rate < max(6.0, conn_th * 0.5):
            apply("命令控制类", "反向Shell可疑", "high", "外连高端口且长会话低频通信")
        if session_duration > 120 and interval_std < 0.1 and req_interval > 0:
            apply("命令控制类", "C&C通信可疑", "high", f"请求间隔标准差{interval_std:.3f}呈周期性")
        if (dst_port == 53 or "dns" in payload_preview) and avg_pkt_size > 100 and conn_freq > scan_th:
            apply("命令控制类", "DNS隧道可疑", "high", f"DNS流量平均包大小{avg_pkt_size:.1f}且频率异常")
        if proto == "ICMP" and avg_pkt_size > 100 and conn_freq > scan_th:
            apply("命令控制类", "ICMP隧道可疑", "high", f"ICMP平均包大小{avg_pkt_size:.1f}且频率异常")

        if src_is_private and dst_is_private and dst_port in {445, 3389} and conn_freq > scan_th:
            apply("横向移动类", "SMB/RDP异常访问", "high", f"内网端口{dst_port}连接频率{conn_freq:.2f}异常")

        if total_bytes > large_bytes_th and session_duration > 60:
            apply("数据泄露类", "异常大数据传输", "high", f"会话总字节{int(total_bytes)}异常偏大")
        if is_sensitive_port and direction == "outbound" and total_bytes > large_bytes_th * 0.5:
            apply("数据泄露类", "敏感端口访问", "high", f"敏感端口外连且数据量{int(total_bytes)}异常")

        if dst_port in {80, 443, 8080} and re.search(r"\b(select|union|insert|delete|drop)\b", payload_preview):
            apply("Web攻击类", "SQL注入攻击", "high", "HTTP载荷出现SQL注入关键字")
        if dst_port in {80, 443, 8080} and re.search(r"(<script|javascript:|onerror=)", payload_preview):
            apply("Web攻击类", "XSS攻击", "medium", "HTTP载荷出现XSS脚本关键字")
        if dst_port in {80, 443, 8080} and re.search(r"(\.\./|\.\\|%2e%2e)", payload_preview):
            apply("Web攻击类", "目录遍历攻击", "medium", "HTTP载荷出现目录遍历特征")

        if session_duration > 600:
            apply("连接异常类", "异常长会话", "medium", f"会话持续时间{session_duration:.1f}s异常")
        if req_interval < 0.05 and conn_freq > conn_th:
            apply("连接异常类", "异常短请求间隔", "medium", f"请求间隔{req_interval:.4f}s且连接频率异常")
        if dst_port_type == "well_known" and sensitive_port_hits >= 5 and conn_freq > scan_th:
            apply("端口与服务类", "服务探测行为", "medium", f"敏感端口命中{sensitive_port_hits}次")

        if role_violation:
            apply("安全策略与权限类", "权限滥用行为", "high", "普通用户尝试管理员操作")

        if is_loopback_pair and level == "high":
            category = "本机回环通信"
            sub = "本地回环高频通信"
            level = "medium"
            reasons.append("回环流量场景已降级处理，避免误报高危扫描")
        elif is_loopback_pair and level == "medium":
            category = "本机回环通信"
            if sub == "端口扫描行为":
                sub = "本地回环高频通信"

        return {"matched": len(reasons) > 0, "level": level, "category": category, "sub_category": sub, "reasons": reasons}
