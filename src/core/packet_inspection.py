from __future__ import annotations

import struct
from collections.abc import Mapping, Sequence

SERVICE_PORT_PROTOCOLS: tuple[tuple[frozenset[int], str], ...] = (
    (frozenset({53}), "DNS"),
    (frozenset({502}), "Modbus/TCP"),
    (frozenset({443, 8443}), "TLS"),
    (frozenset({22}), "SSH"),
    (frozenset({445}), "SMB"),
    (frozenset({3389}), "RDP"),
    (frozenset({21}), "FTP"),
    (frozenset({23}), "Telnet"),
    (frozenset({25, 587}), "SMTP"),
    (frozenset({110, 995}), "POP3"),
    (frozenset({143, 993}), "IMAP"),
)


def decode_raw_bytes(raw_hex: str) -> bytes:
    text = str(raw_hex or "").strip()
    if not text:
        return b""
    try:
        return bytes.fromhex(text)
    except Exception:
        return b""


def extract_ascii(raw_bytes: bytes) -> str:
    if not raw_bytes:
        return ""
    return "".join(chr(b) if 32 <= b <= 126 else "." for b in raw_bytes)


def extract_http_line(raw_bytes: bytes) -> str:
    if not raw_bytes:
        return ""
    try:
        text = raw_bytes.decode("latin-1", errors="ignore")
    except Exception:
        return ""
    first = text.splitlines()[0].strip() if text else ""
    if not first:
        return ""
    methods = ("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "HTTP/")
    for method in methods:
        if first.upper().startswith(method):
            return first[:180]
    return ""


def infer_app_protocol(
    row: Mapping[str, object],
    service_port_protocols: Sequence[tuple[Sequence[int], str]] = SERVICE_PORT_PROTOCOLS,
) -> str:
    proto = str(row.get("proto", "") or "").upper()
    src_port = int(row.get("src_port", 0) or 0)
    dst_port = int(row.get("dst_port", 0) or 0)
    ports = {src_port, dst_port}
    raw_bytes = decode_raw_bytes(str(row.get("raw_hex", "")))
    if extract_http_line(raw_bytes):
        return "HTTP"
    if proto == "UDP" and 443 in ports:
        return "QUIC"
    for service_ports, app_name in service_port_protocols:
        if ports & set(service_ports):
            return app_name
    if proto == "ICMP":
        return "ICMP"
    return proto or "OTHER"


def _format_mac(raw_bytes: bytes) -> str:
    if len(raw_bytes) < 6:
        return ""
    return ":".join(f"{b:02x}" for b in raw_bytes[:6])


def _tcp_flags_text(flags: int) -> str:
    names = [
        (0x01, "FIN"),
        (0x02, "SYN"),
        (0x04, "RST"),
        (0x08, "PSH"),
        (0x10, "ACK"),
        (0x20, "URG"),
        (0x40, "ECE"),
        (0x80, "CWR"),
    ]
    hits = [name for bit, name in names if int(flags) & bit]
    return ",".join(hits) if hits else "NONE"


def dissect_packet_bytes(detail: Mapping[str, object]) -> dict[str, object]:
    raw_bytes = decode_raw_bytes(str(detail.get("raw_hex", "")))
    layers: dict[str, object] = {
        "frame_bytes": raw_bytes,
        "network_bytes": raw_bytes,
        "transport_bytes": b"",
        "payload_bytes": raw_bytes,
        "ethertype": 0,
        "ip_version": 0,
        "ip_proto": 0,
        "src_mac": "",
        "dst_mac": "",
        "tcp_flags": "",
    }
    if len(raw_bytes) < 14:
        return layers
    dst_mac = _format_mac(raw_bytes[0:6])
    src_mac = _format_mac(raw_bytes[6:12])
    ethertype = int.from_bytes(raw_bytes[12:14], "big")
    layers["src_mac"] = src_mac
    layers["dst_mac"] = dst_mac
    layers["ethertype"] = ethertype
    network_offset = 14
    if ethertype == 0x8100 and len(raw_bytes) >= 18:
        ethertype = int.from_bytes(raw_bytes[16:18], "big")
        layers["ethertype"] = ethertype
        network_offset = 18
    if ethertype == 0x0800 and len(raw_bytes) >= network_offset + 20:
        ihl = (raw_bytes[network_offset] & 0x0F) * 4
        if ihl < 20 or len(raw_bytes) < network_offset + ihl:
            return layers
        layers["ip_version"] = 4
        layers["ip_proto"] = raw_bytes[network_offset + 9]
        layers["network_bytes"] = raw_bytes[network_offset : network_offset + ihl]
        transport_offset = network_offset + ihl
    elif ethertype == 0x86DD and len(raw_bytes) >= network_offset + 40:
        layers["ip_version"] = 6
        layers["ip_proto"] = raw_bytes[network_offset + 6]
        layers["network_bytes"] = raw_bytes[network_offset : network_offset + 40]
        transport_offset = network_offset + 40
    else:
        return layers
    proto = str(detail.get("proto", "") or "").upper()
    if proto == "TCP" and len(raw_bytes) >= transport_offset + 20:
        data_offset = ((raw_bytes[transport_offset + 12] >> 4) & 0x0F) * 4
        if data_offset < 20 or len(raw_bytes) < transport_offset + data_offset:
            return layers
        flags = int(raw_bytes[transport_offset + 13])
        layers["transport_bytes"] = raw_bytes[transport_offset : transport_offset + data_offset]
        layers["payload_bytes"] = raw_bytes[transport_offset + data_offset :]
        layers["tcp_flags"] = _tcp_flags_text(flags)
        return layers
    if proto == "UDP" and len(raw_bytes) >= transport_offset + 8:
        layers["transport_bytes"] = raw_bytes[transport_offset : transport_offset + 8]
        layers["payload_bytes"] = raw_bytes[transport_offset + 8 :]
        return layers
    if proto == "ICMP" and len(raw_bytes) >= transport_offset + 4:
        layers["transport_bytes"] = raw_bytes[transport_offset : transport_offset + 4]
        layers["payload_bytes"] = raw_bytes[transport_offset + 4 :]
    return layers


def _modbus_function_name(func_code: int) -> str:
    mapping = {
        1: "Read Coils",
        2: "Read Discrete Inputs",
        3: "Read Holding Registers",
        4: "Read Input Registers",
        5: "Write Single Coil",
        6: "Write Single Register",
        15: "Write Multiple Coils",
        16: "Write Multiple Registers",
        22: "Mask Write Register",
        23: "Read/Write Multiple Registers",
    }
    base = int(func_code or 0) & 0x7F
    name = mapping.get(base, f"Function {base}")
    if int(func_code or 0) & 0x80:
        return f"{name} Exception"
    return name


def parse_modbus_fields(payload: bytes, detail: Mapping[str, object]) -> dict[str, str]:
    if len(payload) < 8:
        return {}
    protocol_id = int.from_bytes(payload[2:4], "big")
    if protocol_id != 0:
        return {}
    mbap_len = int.from_bytes(payload[4:6], "big")
    unit_id = payload[6]
    func_code = payload[7]
    pdu = payload[8:]
    is_response = int(detail.get("src_port", 0) or 0) == 502
    fields: dict[str, str] = {
        "transaction_id": str(int.from_bytes(payload[0:2], "big")),
        "protocol_id": str(protocol_id),
        "mbap_length": str(mbap_len),
        "unit_id": str(unit_id),
        "function_code": f"0x{func_code:02x}",
        "function_name": _modbus_function_name(func_code),
        "direction": "response" if is_response else "request",
    }
    if func_code & 0x80:
        if pdu:
            fields["exception_code"] = f"0x{pdu[0]:02x}"
    else:
        base_code = func_code & 0x7F
        if base_code in {1, 2, 3, 4}:
            if not is_response and len(pdu) >= 4:
                fields["start_address"] = str(int.from_bytes(pdu[0:2], "big"))
                fields["quantity"] = str(int.from_bytes(pdu[2:4], "big"))
            elif pdu:
                byte_count = pdu[0]
                fields["byte_count"] = str(byte_count)
                data = pdu[1 : 1 + byte_count]
                words = [str(int.from_bytes(data[i : i + 2], "big")) for i in range(0, min(len(data), 16), 2) if i + 1 < len(data)]
                if words:
                    fields["data_preview"] = ", ".join(words[:8])
        elif base_code in {5, 6} and len(pdu) >= 4:
            fields["address"] = str(int.from_bytes(pdu[0:2], "big"))
            fields["value"] = f"0x{int.from_bytes(pdu[2:4], 'big'):04x}"
        elif base_code in {15, 16} and len(pdu) >= 4:
            fields["start_address"] = str(int.from_bytes(pdu[0:2], "big"))
            fields["quantity"] = str(int.from_bytes(pdu[2:4], "big"))
            if not is_response and len(pdu) >= 5:
                byte_count = pdu[4]
                fields["byte_count"] = str(byte_count)
                data = pdu[5 : 5 + byte_count]
                if data:
                    fields["data_preview_hex"] = data[:16].hex()
    target = (
        f"addr={fields['start_address']} qty={fields['quantity']}"
        if "start_address" in fields and "quantity" in fields
        else f"addr={fields['address']}"
        if "address" in fields
        else ""
    )
    if target:
        fields["target"] = target
    return fields


def parse_http_fields(raw_bytes: bytes) -> dict[str, str]:
    if not raw_bytes:
        return {}
    try:
        text = raw_bytes.decode("latin-1", errors="ignore")
    except Exception:
        return {}
    if not text:
        return {}
    lines = text.splitlines()
    if not lines:
        return {}
    first_line = lines[0].strip()
    first_upper = first_line.upper()
    methods = ("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ")
    is_http = first_upper.startswith("HTTP/") or any(first_upper.startswith(method) for method in methods)
    if not is_http:
        return {}
    fields: dict[str, str] = {"first_line": first_line[:180]}
    if first_upper.startswith("HTTP/"):
        parts = first_line.split(" ", 2)
        if len(parts) >= 2:
            fields["status_code"] = parts[1]
        if len(parts) >= 3:
            fields["status_text"] = parts[2][:120]
    else:
        parts = first_line.split(" ", 2)
        if len(parts) >= 1:
            fields["method"] = parts[0]
        if len(parts) >= 2:
            fields["path"] = parts[1][:160]
    for raw_line in lines[1:40]:
        line = raw_line.strip()
        if not line:
            break
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        normalized = key.strip().lower().replace("-", "_")
        value_text = value.strip()
        if normalized in {"host", "user_agent", "content_type", "authorization", "cookie", "server", "location"}:
            fields[normalized] = value_text[:200]
    return fields


def _dns_read_name(data: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
    labels: list[str] = []
    pos = int(offset)
    end = pos
    jumped = False
    if depth > 8:
        return "", end
    while pos < len(data):
        length = data[pos]
        if length == 0:
            end = pos + 1 if not jumped else end
            pos += 1
            break
        if (length & 0xC0) == 0xC0:
            if pos + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[pos + 1]
            sub_name, _ = _dns_read_name(data, pointer, depth + 1)
            if sub_name:
                labels.append(sub_name)
            end = pos + 2 if not jumped else end
            jumped = True
            pos += 2
            break
        pos += 1
        if pos + length > len(data):
            break
        label = data[pos : pos + length].decode("ascii", errors="replace")
        labels.append(label)
        pos += length
        if not jumped:
            end = pos
    return ".".join(part for part in labels if part), end


def _dns_type_name(qtype: int) -> str:
    mapping = {
        1: "A",
        2: "NS",
        5: "CNAME",
        6: "SOA",
        12: "PTR",
        15: "MX",
        16: "TXT",
        28: "AAAA",
        33: "SRV",
    }
    return mapping.get(int(qtype), str(qtype))


def parse_dns_fields(raw_bytes: bytes) -> dict[str, str]:
    if len(raw_bytes) < 12:
        return {}
    try:
        dns_id, flags, qdcount, ancount, _nscount, _arcount = struct.unpack("!HHHHHH", raw_bytes[:12])
    except Exception:
        return {}
    if qdcount <= 0 or qdcount > 20:
        return {}
    offset = 12
    query_name, offset = _dns_read_name(raw_bytes, offset)
    if not query_name or offset + 4 > len(raw_bytes):
        return {}
    try:
        qtype, qclass = struct.unpack("!HH", raw_bytes[offset : offset + 4])
    except Exception:
        return {}
    fields = {
        "id": str(dns_id),
        "query": query_name[:220],
        "query_type": _dns_type_name(qtype),
        "question_count": str(qdcount),
        "answer_count": str(ancount),
        "qr": "response" if (flags & 0x8000) else "query",
    }
    if qclass == 1:
        fields["class"] = "IN"
    return fields


def parse_tls_fields(raw_bytes: bytes) -> dict[str, str]:
    if len(raw_bytes) < 9 or raw_bytes[0] != 0x16 or raw_bytes[1] != 0x03:
        return {}
    record_len = (raw_bytes[3] << 8) | raw_bytes[4]
    if len(raw_bytes) < 5 + record_len:
        return {}
    if raw_bytes[5] != 0x01:
        return {"record_type": "handshake", "handshake_type": str(raw_bytes[5])}
    offset = 43
    if len(raw_bytes) < offset or offset >= len(raw_bytes):
        return {}
    session_len = raw_bytes[offset]
    offset += 1 + session_len
    if offset + 2 > len(raw_bytes):
        return {}
    cipher_len = int.from_bytes(raw_bytes[offset : offset + 2], "big")
    offset += 2 + cipher_len
    if offset >= len(raw_bytes):
        return {}
    comp_len = raw_bytes[offset]
    offset += 1 + comp_len
    if offset + 2 > len(raw_bytes):
        return {"record_type": "tls", "handshake": "ClientHello"}
    ext_len = int.from_bytes(raw_bytes[offset : offset + 2], "big")
    offset += 2
    end = min(len(raw_bytes), offset + ext_len)
    fields: dict[str, str] = {"record_type": "tls", "handshake": "ClientHello"}
    extractors = {
        0: lambda data: (
            "sni",
            data[5 : min(len(data), 5 + int.from_bytes(data[3:5], "big"))].decode("ascii", errors="replace")[:220],
        )
        if len(data) >= 5
        else None,
        16: lambda data: ("alpn", data[3 : 3 + data[2]].decode("ascii", errors="replace")[:120]) if len(data) >= 3 else None,
    }
    while offset + 4 <= end:
        ext_type = int.from_bytes(raw_bytes[offset : offset + 2], "big")
        ext_size = int.from_bytes(raw_bytes[offset + 2 : offset + 4], "big")
        ext_data = raw_bytes[offset + 4 : offset + 4 + ext_size]
        if len(ext_data) < ext_size:
            break
        extractor = extractors.get(ext_type)
        if extractor:
            try:
                item = extractor(ext_data)
                if item and item[1]:
                    fields[item[0]] = item[1]
            except Exception:
                pass
        offset += 4 + ext_size
    return fields


def extract_app_fields(
    detail: Mapping[str, object],
    service_port_protocols: Sequence[tuple[Sequence[int], str]] = SERVICE_PORT_PROTOCOLS,
) -> tuple[str, dict[str, str]]:
    layers = dissect_packet_bytes(detail)
    payload_bytes = bytes(layers.get("payload_bytes", b"") or b"")
    http_fields = parse_http_fields(payload_bytes)
    if http_fields:
        return "HTTP", http_fields
    src_port = int(detail.get("src_port", 0) or 0)
    dst_port = int(detail.get("dst_port", 0) or 0)
    ports = {src_port, dst_port}
    if 502 in ports:
        modbus_fields = parse_modbus_fields(payload_bytes, detail)
        if modbus_fields:
            return "Modbus/TCP", modbus_fields
        return "Modbus/TCP", {
            "direction": "response" if src_port == 502 else "request",
            "note": "当前包无完整Modbus PDU，可能是ACK/握手控制包",
        }
    tls_fields = parse_tls_fields(payload_bytes)
    if tls_fields or ports & {443, 8443}:
        return "TLS", tls_fields
    dns_bytes = payload_bytes
    if str(detail.get("proto", "") or "").upper() == "TCP" and len(payload_bytes) >= 2:
        advertised = int.from_bytes(payload_bytes[:2], "big")
        if advertised == len(payload_bytes) - 2:
            dns_bytes = payload_bytes[2:]
    dns_fields = parse_dns_fields(dns_bytes)
    if dns_fields or 53 in ports:
        return "DNS", dns_fields
    return infer_app_protocol(detail, service_port_protocols=service_port_protocols), {}


__all__ = [
    "SERVICE_PORT_PROTOCOLS",
    "decode_raw_bytes",
    "dissect_packet_bytes",
    "extract_app_fields",
    "extract_ascii",
    "extract_http_line",
    "infer_app_protocol",
    "parse_dns_fields",
    "parse_http_fields",
    "parse_modbus_fields",
    "parse_tls_fields",
]
