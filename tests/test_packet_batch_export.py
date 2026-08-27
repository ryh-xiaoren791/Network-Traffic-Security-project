from __future__ import annotations

import base64
import csv
import json
import tempfile
import unittest
from pathlib import Path

from src.core.ctf.batch_export import PacketBatchExportService


def build_tcp_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq: int,
    payload: bytes,
) -> str:
    def ip_bytes(ip_text: str) -> bytes:
        return bytes(int(part) for part in ip_text.split("."))

    ethernet = bytes.fromhex("00112233445566778899aabb0800")
    total_length = 20 + 20 + len(payload)
    ip_header = bytearray([0x45, 0x00, (total_length >> 8) & 0xFF, total_length & 0xFF, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00])
    ip_header.extend(ip_bytes(src_ip))
    ip_header.extend(ip_bytes(dst_ip))
    tcp_header = bytearray()
    tcp_header.extend(int(src_port).to_bytes(2, "big"))
    tcp_header.extend(int(dst_port).to_bytes(2, "big"))
    tcp_header.extend(int(seq).to_bytes(4, "big"))
    tcp_header.extend((0).to_bytes(4, "big"))
    tcp_header.extend(bytes([0x50, 0x18]))
    tcp_header.extend((1024).to_bytes(2, "big"))
    tcp_header.extend((0).to_bytes(2, "big"))
    tcp_header.extend((0).to_bytes(2, "big"))
    return (ethernet + bytes(ip_header) + bytes(tcp_header) + payload).hex()


def build_udp_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    payload: bytes,
) -> str:
    def ip_bytes(ip_text: str) -> bytes:
        return bytes(int(part) for part in ip_text.split("."))

    ethernet = bytes.fromhex("00112233445566778899aabb0800")
    total_length = 20 + 8 + len(payload)
    ip_header = bytearray([0x45, 0x00, (total_length >> 8) & 0xFF, total_length & 0xFF, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00])
    ip_header.extend(ip_bytes(src_ip))
    ip_header.extend(ip_bytes(dst_ip))
    udp_len = 8 + len(payload)
    udp_header = bytearray()
    udp_header.extend(int(src_port).to_bytes(2, "big"))
    udp_header.extend(int(dst_port).to_bytes(2, "big"))
    udp_header.extend(int(udp_len).to_bytes(2, "big"))
    udp_header.extend((0).to_bytes(2, "big"))
    return (ethernet + bytes(ip_header) + bytes(udp_header) + payload).hex()


class PacketBatchExportServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.service = PacketBatchExportService()

    def test_extract_field_rows_http(self) -> None:
        payload = b"GET /flag HTTP/1.1\r\nHost: demo.ctf.local\r\n\r\n"
        rows = self.service.extract_field_rows(
            [
                {
                    "id": 1,
                    "ts": "2024-01-01 00:00:01",
                    "source": "offline",
                    "risk_level": "medium",
                    "src_ip": "10.0.0.1",
                    "src_port": 1234,
                    "dst_ip": "10.0.0.2",
                    "dst_port": 80,
                    "proto": "TCP",
                    "length": len(payload),
                    "process_name": "demo",
                    "raw_hex": build_tcp_packet("10.0.0.1", "10.0.0.2", 1234, 80, 1, payload),
                }
            ]
        )
        self.assertEqual(rows[0]["app_protocol"], "HTTP")
        self.assertEqual(rows[0]["http_host"], "demo.ctf.local")
        self.assertIn("GET /flag HTTP/1.1", rows[0]["http_request"])

    def test_extract_field_rows_dns(self) -> None:
        dns_query = bytes.fromhex("12340100000100000000000003777777076578616d706c6503636f6d0000010001")
        rows = self.service.extract_field_rows(
            [
                {
                    "id": 2,
                    "ts": "2024-01-01 00:00:02",
                    "source": "offline",
                    "risk_level": "normal",
                    "src_ip": "1.1.1.1",
                    "src_port": 53000,
                    "dst_ip": "8.8.8.8",
                    "dst_port": 53,
                    "proto": "UDP",
                    "length": len(dns_query),
                    "process_name": "",
                    "raw_hex": build_udp_packet("1.1.1.1", "8.8.8.8", 53000, 53, dns_query),
                }
            ]
        )
        self.assertEqual(rows[0]["app_protocol"], "DNS")
        self.assertEqual(rows[0]["dns_qname"], "www.example.com")

    def test_extract_field_rows_modbus(self) -> None:
        payload = bytes([0, 1, 0, 0, 0, 6, 1, 3, 0, 5, 0, 2])
        rows = self.service.extract_field_rows(
            [
                {
                    "id": 3,
                    "ts": "2024-01-01 00:00:03",
                    "source": "offline",
                    "risk_level": "high",
                    "src_ip": "192.168.1.10",
                    "src_port": 40000,
                    "dst_ip": "192.168.1.20",
                    "dst_port": 502,
                    "proto": "TCP",
                    "length": len(payload),
                    "process_name": "",
                    "raw_hex": build_tcp_packet("192.168.1.10", "192.168.1.20", 40000, 502, 1, payload),
                }
            ]
        )
        self.assertEqual(rows[0]["app_protocol"], "Modbus/TCP")
        self.assertIn("addr=5 qty=2", rows[0]["modbus_summary"])

    def test_export_field_rows_csv_and_json(self) -> None:
        rows = [
            {
                "id": 1,
                "ts": "2024-01-01 00:00:01",
                "source": "offline",
                "risk_level": "normal",
                "src_ip": "1.1.1.1",
                "src_port": 1,
                "dst_ip": "2.2.2.2",
                "dst_port": 2,
                "proto": "TCP",
                "length": 10,
                "process_name": "demo",
                "app_protocol": "HTTP",
                "http_request": "GET / HTTP/1.1",
                "http_host": "example.com",
                "dns_qname": "",
                "tls_sni": "",
                "modbus_summary": "",
                "payload_ascii_preview": "GET /",
                "payload_hex_preview": "474554",
            }
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_out = Path(temp_dir) / "fields.csv"
            json_out = Path(temp_dir) / "fields.json"
            self.service.export_field_rows(rows, csv_out, "csv")
            self.service.export_field_rows(rows, json_out, "json")
            with csv_out.open("r", encoding="utf-8") as handle:
                csv_rows = list(csv.DictReader(handle))
            json_rows = json.loads(json_out.read_text(encoding="utf-8"))
        self.assertEqual(csv_rows[0]["http_host"], "example.com")
        self.assertEqual(json_rows[0]["app_protocol"], "HTTP")

    def test_extract_flow_rows_and_candidates(self) -> None:
        base32_text = "MMYWMX3GNEYWOXZRGAYDA==="
        packet_details = []
        for index in range(0, len(base32_text), 2):
            chunk = base32_text[index : index + 2].encode("ascii")
            payload = bytes([0, 1, 0, 0, 0, 6, 1, 3, 0, 5]) + chunk
            packet_details.append(
                {
                    "id": index + 1,
                    "ts": f"2024-01-01 00:00:{index + 1:02d}",
                    "ts_epoch": float(index + 1),
                    "source": "offline",
                    "risk_level": "medium",
                    "src_ip": "192.168.1.10",
                    "src_port": 40000,
                    "dst_ip": "192.168.1.20",
                    "dst_port": 502,
                    "proto": "TCP",
                    "length": len(payload),
                    "process_name": "",
                    "raw_hex": build_tcp_packet("192.168.1.10", "192.168.1.20", 40000, 502, 1000 + index, payload),
                }
            )
        flow_rows = self.service.extract_flow_rows(packet_details)
        candidate_rows = self.service.extract_candidate_rows(packet_details)
        self.assertEqual(len(flow_rows), 1)
        self.assertEqual(flow_rows[0]["candidate_count"], 1)
        self.assertTrue(candidate_rows)
        self.assertEqual(candidate_rows[0]["encoding"], "base32")
        self.assertIn("c1f_fi1g_1000", candidate_rows[0]["decoded_text"])

    def test_export_flow_rows_and_candidate_rows(self) -> None:
        flow_rows = [
            {
                "flow_index": 1,
                "source": "offline",
                "proto": "TCP",
                "endpoint_a": "1.1.1.1:1",
                "endpoint_b": "2.2.2.2:2",
                "packet_count": 3,
                "segment_count": 2,
                "client_payload_size": 10,
                "server_payload_size": 12,
                "candidate_count": 1,
                "asset_count": 0,
                "object_count": 0,
                "top_candidate_encoding": "base32",
                "top_candidate_preview": "flag",
                "client_ascii_preview": "abc",
                "server_ascii_preview": "xyz",
                "packet_ids": [1, 2, 3],
            }
        ]
        candidate_rows = [
            {
                "flow_index": 1,
                "source": "offline",
                "proto": "TCP",
                "endpoint_a": "1.1.1.1:1",
                "endpoint_b": "2.2.2.2:2",
                "encoding": "base32",
                "direction": "C->S",
                "source_kind": "fragmented",
                "confidence": "high",
                "value": "MMYWMX3G",
                "decoded_text": "demo",
                "packet_ids": [1, 2],
            }
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            flow_csv = Path(temp_dir) / "flows.csv"
            candidate_json = Path(temp_dir) / "candidates.json"
            self.service.export_flow_rows(flow_rows, flow_csv, "csv")
            self.service.export_candidate_rows(candidate_rows, candidate_json, "json")
            with flow_csv.open("r", encoding="utf-8") as handle:
                csv_rows = list(csv.DictReader(handle))
            json_rows = json.loads(candidate_json.read_text(encoding="utf-8"))
        self.assertEqual(csv_rows[0]["top_candidate_encoding"], "base32")
        self.assertEqual(json_rows[0]["decoded_text"], "demo")

    def test_candidate_decode_chain_applies_second_stage(self) -> None:
        inner = base64.b64encode(b"flag{demo}").decode("ascii")
        outer = base64.b32encode(inner.encode("ascii")).decode("ascii")
        packet_details = [
            {
                "id": 1,
                "ts": "2024-01-01 00:00:01",
                "ts_epoch": 1.0,
                "source": "offline",
                "risk_level": "medium",
                "src_ip": "10.0.0.1",
                "src_port": 1234,
                "dst_ip": "10.0.0.2",
                "dst_port": 80,
                "proto": "TCP",
                "length": len(outer),
                "process_name": "",
                "raw_hex": build_tcp_packet("10.0.0.1", "10.0.0.2", 1234, 80, 1, outer.encode("ascii")),
            }
        ]
        candidate_rows = self.service.extract_candidate_rows(packet_details)
        self.assertTrue(candidate_rows)
        self.assertIn("base32 -> base64", candidate_rows[0]["decode_chain"])
        self.assertIn("flag{demo}", candidate_rows[0]["final_preview"])

    def test_export_flow_body_bundle(self) -> None:
        packet_details = [
            {
                "id": 1,
                "ts": "2024-01-01 00:00:01",
                "ts_epoch": 1.0,
                "source": "offline",
                "risk_level": "normal",
                "src_ip": "10.0.0.1",
                "src_port": 1111,
                "dst_ip": "10.0.0.2",
                "dst_port": 2222,
                "proto": "TCP",
                "length": 5,
                "process_name": "",
                "raw_hex": build_tcp_packet("10.0.0.1", "10.0.0.2", 1111, 2222, 1, b"hello"),
            },
            {
                "id": 2,
                "ts": "2024-01-01 00:00:02",
                "ts_epoch": 2.0,
                "source": "offline",
                "risk_level": "normal",
                "src_ip": "10.0.0.2",
                "src_port": 2222,
                "dst_ip": "10.0.0.1",
                "dst_port": 1111,
                "proto": "TCP",
                "length": 5,
                "process_name": "",
                "raw_hex": build_tcp_packet("10.0.0.2", "10.0.0.1", 2222, 1111, 1, b"world"),
            },
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            out_dir = Path(temp_dir) / "bundle"
            self.service.export_flow_body_bundle(packet_details, out_dir)
            index_file = out_dir / "index.json"
            self.assertTrue(index_file.exists())
            index_rows = json.loads(index_file.read_text(encoding="utf-8"))
            self.assertTrue(index_rows)
            first = index_rows[0]
            self.assertTrue((out_dir / first["interleaved_file"]).exists())
            self.assertTrue((out_dir / first["client_bin_file"]).exists())


if __name__ == "__main__":
    unittest.main()
