from src.core.ctf import build_packet_ctf_clues


def build_udp_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes) -> str:
    def ip_bytes(ip_text: str) -> bytes:
        return bytes(int(part) for part in ip_text.split("."))

    ethernet = bytes.fromhex("00112233445566778899aabb0800")
    total_length = 20 + 8 + len(payload)
    ip_header = bytearray(
        [
            0x45,
            0x00,
            (total_length >> 8) & 0xFF,
            total_length & 0xFF,
            0x00,
            0x01,
            0x00,
            0x00,
            0x40,
            0x11,
            0x00,
            0x00,
        ]
    )
    ip_header.extend(ip_bytes(src_ip))
    ip_header.extend(ip_bytes(dst_ip))
    udp_len = 8 + len(payload)
    udp_header = bytearray()
    udp_header.extend(int(src_port).to_bytes(2, "big"))
    udp_header.extend(int(dst_port).to_bytes(2, "big"))
    udp_header.extend(int(udp_len).to_bytes(2, "big"))
    udp_header.extend((0).to_bytes(2, "big"))
    return (ethernet + bytes(ip_header) + bytes(udp_header) + payload).hex()


def test_build_packet_ctf_clues_extracts_dns_and_outbound_signals() -> None:
    dns_payload = bytes.fromhex("1a2b01000001000000000000076578616d706c6503636f6d0000010001")
    row = {
        "id": 1,
        "src_ip": "10.0.0.8",
        "dst_ip": "8.8.8.8",
        "src_port": 53000,
        "dst_port": 53,
        "proto": "UDP",
        "process_name": "chrome.exe",
        "risk_level": "normal",
        "length": 128,
        "raw_hex": build_udp_packet("10.0.0.8", "8.8.8.8", 53000, 53, dns_payload),
    }
    clues = build_packet_ctf_clues([row])
    types = {str(item["type"]) for item in clues}
    assert "域名请求" in types
    assert "外联" in types
    assert "明文可读" in types


def test_build_packet_ctf_clues_marks_suspicious_process_sensitive_port_and_large_payload() -> None:
    row = {
        "id": 2,
        "src_ip": "10.0.0.8",
        "dst_ip": "203.0.113.10",
        "src_port": 53001,
        "dst_port": 4444,
        "proto": "TCP",
        "process_name": "powershell.exe",
        "risk_level": "normal",
        "length": 4096,
        "raw_hex": "",
    }
    clues = build_packet_ctf_clues([row], large_payload_bytes=1200)
    types = {str(item["type"]) for item in clues}
    assert "可疑进程" in types
    assert "敏感端口" in types
    assert "大载荷" in types


def test_build_packet_ctf_clues_deduplicates_risk_and_keeps_higher_level() -> None:
    rows = [
        {
            "id": 3,
            "src_ip": "10.0.0.8",
            "dst_ip": "8.8.8.8",
            "src_port": 53002,
            "dst_port": 443,
            "proto": "TCP",
            "process_name": "curl.exe",
            "risk_level": "medium",
            "length": 256,
            "raw_hex": "",
        },
        {
            "id": 4,
            "src_ip": "10.0.0.8",
            "dst_ip": "8.8.8.8",
            "src_port": 53003,
            "dst_port": 443,
            "proto": "TCP",
            "process_name": "curl.exe",
            "risk_level": "high",
            "length": 256,
            "raw_hex": "",
        },
    ]
    clues = build_packet_ctf_clues(rows)
    risk_clues = [item for item in clues if item["type"] == "风险流量"]
    assert len(risk_clues) == 1
    assert risk_clues[0]["level_key"] == "high"
    assert risk_clues[0]["packet_id"] == 4
