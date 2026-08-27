from src.core.packet_inspection import (
    decode_raw_bytes,
    dissect_packet_bytes,
    extract_app_fields,
    extract_ascii,
    extract_http_line,
    infer_app_protocol,
    parse_dns_fields,
)


def test_decode_raw_bytes_rejects_invalid_hex() -> None:
    assert decode_raw_bytes("xyz") == b""


def test_extract_ascii_and_http_line() -> None:
    payload = b"GET /flag HTTP/1.1\r\nHost: example.com\r\n\r\n"
    assert "GET /flag HTTP/1.1" in extract_ascii(payload)
    assert extract_http_line(payload) == "GET /flag HTTP/1.1"


def test_infer_app_protocol_prefers_http_payload() -> None:
    row = {
        "proto": "TCP",
        "src_port": 51514,
        "dst_port": 8080,
        "raw_hex": b"GET / HTTP/1.1\r\n\r\n".hex(),
    }
    assert infer_app_protocol(row) == "HTTP"


def test_extract_app_fields_parses_http_request() -> None:
    detail = {
        "proto": "TCP",
        "src_port": 51514,
        "dst_port": 80,
        "raw_hex": (
            "00112233445566778899aabb08004500003c00010000400600000a0000010a000002"
            "c93a005000000001000000005018200000000000"
            "474554202f666c616720485454502f312e310d0a486f73743a206578616d706c652e636f6d0d0a0d0a"
        ),
    }
    app_proto, fields = extract_app_fields(detail)
    assert app_proto == "HTTP"
    assert fields["method"] == "GET"
    assert fields["host"] == "example.com"


def test_dissect_packet_bytes_extracts_transport_and_payload() -> None:
    detail = {
        "proto": "TCP",
        "raw_hex": (
            "00112233445566778899aabb08004500003800010000400600000a0000010a000002"
            "303900500000000100000000501220000000000068656c6c6f"
        ),
    }
    layers = dissect_packet_bytes(detail)
    assert layers["ip_version"] == 4
    assert layers["tcp_flags"] == "SYN,ACK"
    assert layers["payload_bytes"] == b"hello"


def test_parse_dns_fields_extracts_query_name() -> None:
    raw_bytes = bytes.fromhex("1a2b01000001000000000000076578616d706c6503636f6d0000010001")
    fields = parse_dns_fields(raw_bytes)
    assert fields["query"] == "example.com"
    assert fields["query_type"] == "A"
