from __future__ import annotations

import base64
import csv
import json
import tempfile
import unittest
from pathlib import Path

from src.core.ctf.service import FlowWorkbenchService


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
            0x06,
            0x00,
            0x00,
        ]
    )
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
    include_ethernet: bool = True,
) -> str:
    def ip_bytes(ip_text: str) -> bytes:
        return bytes(int(part) for part in ip_text.split("."))

    ethernet = bytes.fromhex("00112233445566778899aabb0800") if include_ethernet else b""
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


class FlowWorkbenchServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.service = FlowWorkbenchService()

    def test_decode_payload_by_mode_ascii(self) -> None:
        rendered = self.service.decode_payload_by_mode(b"hello-world", "ascii")
        self.assertIn("hello-world", rendered)

    def test_decode_payload_by_mode_supports_multiple_modes(self) -> None:
        self.assertIn("A", self.service.decode_payload_by_mode(b"A", "utf-8"))
        self.assertIn("QQ==", self.service.decode_payload_by_mode(b"A", "base64"))
        self.assertIn("00000000", self.service.decode_payload_by_mode(b"A", "hex"))
        self.assertEqual(self.service.decode_payload_by_mode(b"", "ascii"), "(empty)")

    def test_decode_raw_bytes_handles_invalid_input(self) -> None:
        self.assertEqual(self.service.decode_raw_bytes("zz-not-hex"), b"")

    def test_merge_tcp_segments_removes_overlap(self) -> None:
        rows = [
            {
                "id": 1,
                "ts": "2024-01-01 00:00:01",
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "src_port": 1234,
                "dst_port": 80,
                "proto": "TCP",
                "raw_hex": build_tcp_packet("10.0.0.1", "10.0.0.2", 1234, 80, seq=100, payload=b"HELLO"),
            },
            {
                "id": 2,
                "ts": "2024-01-01 00:00:02",
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "src_port": 1234,
                "dst_port": 80,
                "proto": "TCP",
                "raw_hex": build_tcp_packet("10.0.0.1", "10.0.0.2", 1234, 80, seq=103, payload=b"LO-WORLD"),
            },
        ]
        analysis = self.service.analyze_flow(rows, anchor_src="10.0.0.1", anchor_sport=1234)
        self.assertEqual(analysis["client_to_server"]["payload_bytes"], b"HELLO-WORLD")

    def test_detects_fragmented_base32_candidate(self) -> None:
        base32_text = "MMYWMX3GNEYWOXZRGAYDA==="
        rows = []
        for index in range(0, len(base32_text), 2):
            chunk = base32_text[index : index + 2].encode("ascii")
            payload = bytes([index + 1, 0, 0, 0, 0, 6, 1, 3, 0, 5]) + chunk
            rows.append(
                {
                    "id": index + 1,
                    "ts": f"2024-01-01 00:00:{index + 1:02d}",
                    "src_ip": "192.168.1.10",
                    "dst_ip": "192.168.1.20",
                    "src_port": 40000,
                    "dst_port": 502,
                    "proto": "TCP",
                    "raw_hex": build_tcp_packet("192.168.1.10", "192.168.1.20", 40000, 502, seq=1000 + index, payload=payload),
                }
            )
        analysis = self.service.analyze_flow(rows, anchor_src="192.168.1.10", anchor_sport=40000)
        hits = [row for row in analysis["candidates"] if row["encoding"] == "base32"]
        self.assertTrue(hits)
        best_hit = hits[0]
        self.assertEqual(best_hit["value"], base32_text)
        self.assertIn("c1f_fi1g_1000", best_hit["decoded_text"])

    def test_detects_contiguous_base64_candidate(self) -> None:
        secret = base64.b64encode(b"flag{demo}").decode("ascii")
        rows = [
            {
                "id": 1,
                "ts": "2024-01-01 00:00:01",
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "src_port": 1234,
                "dst_port": 80,
                "proto": "TCP",
                "raw_hex": build_tcp_packet("10.0.0.1", "10.0.0.2", 1234, 80, seq=1, payload=secret.encode("ascii")),
            }
        ]
        analysis = self.service.analyze_flow(rows, anchor_src="10.0.0.1", anchor_sport=1234)
        hits = [row for row in analysis["candidates"] if row["encoding"] == "base64"]
        self.assertTrue(hits)
        self.assertIn("flag{demo}", hits[0]["decoded_text"])

    def test_detects_contiguous_hex_candidate(self) -> None:
        hex_text = b"4142434445464748"
        rows = [
            {
                "id": 1,
                "ts": "2024-01-01 00:00:01",
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "src_port": 1234,
                "dst_port": 80,
                "proto": "TCP",
                "raw_hex": build_tcp_packet("10.0.0.1", "10.0.0.2", 1234, 80, seq=1, payload=hex_text),
            }
        ]
        analysis = self.service.analyze_flow(rows, anchor_src="10.0.0.1", anchor_sport=1234)
        hits = [row for row in analysis["candidates"] if row["encoding"] == "hex"]
        self.assertTrue(hits)
        self.assertIn("ABCDEFGH", hits[0]["decoded_text"])

    def test_extracts_http_assets(self) -> None:
        payload = b"GET /flag HTTP/1.1\r\nHost: ctf.example.com\r\n\r\nVisit https://ctf.example.com/flag"
        rows = [
            {
                "id": 1,
                "ts": "2024-01-01 00:00:01",
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "src_port": 1234,
                "dst_port": 80,
                "proto": "TCP",
                "raw_hex": build_tcp_packet("10.0.0.1", "10.0.0.2", 1234, 80, seq=1, payload=payload),
            }
        ]
        analysis = self.service.analyze_flow(rows, anchor_src="10.0.0.1", anchor_sport=1234)
        assets = analysis["assets"]
        values = [row["value"] for row in assets]
        self.assertIn("GET /flag HTTP/1.1", values)
        self.assertIn("ctf.example.com", values)
        self.assertIn("https://ctf.example.com/flag", values)

    def test_extracts_modbus_assets(self) -> None:
        payload = bytes([0, 1, 0, 0, 0, 6, 1, 3, 0, 10, 0, 2])
        rows = [
            {
                "id": 1,
                "ts": "2024-01-01 00:00:01",
                "src_ip": "192.168.1.10",
                "dst_ip": "192.168.1.20",
                "src_port": 40000,
                "dst_port": 502,
                "proto": "TCP",
                "raw_hex": build_tcp_packet("192.168.1.10", "192.168.1.20", 40000, 502, seq=100, payload=payload),
            }
        ]
        analysis = self.service.analyze_flow(rows, anchor_src="192.168.1.10", anchor_sport=40000)
        modbus_assets = [row for row in analysis["assets"] if row["asset_type"] == "modbus"]
        self.assertTrue(modbus_assets)
        self.assertIn("addr=10 qty=2", modbus_assets[0]["value"])

    def test_carves_png_object(self) -> None:
        png_blob = b"\x89PNG\r\n\x1a\nIHDRdemo-dataIEND\xaeB`\x82"
        rows = [
            {
                "id": 1,
                "ts": "2024-01-01 00:00:01",
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "src_port": 1234,
                "dst_port": 80,
                "proto": "TCP",
                "raw_hex": build_tcp_packet("10.0.0.1", "10.0.0.2", 1234, 80, seq=1, payload=png_blob),
            }
        ]
        analysis = self.service.analyze_flow(rows, anchor_src="10.0.0.1", anchor_sport=1234)
        objects = [row for row in analysis["objects"] if row["object_type"] == "png"]
        self.assertTrue(objects)
        self.assertGreaterEqual(objects[0]["size"], len(png_blob))

    def test_carves_zip_object(self) -> None:
        zip_blob = b"PK\x03\x04demo-dataPK\x05\x06" + (0).to_bytes(16, "little") + (0).to_bytes(2, "little")
        rows = [
            {
                "id": 1,
                "ts": "2024-01-01 00:00:01",
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "src_port": 1234,
                "dst_port": 80,
                "proto": "TCP",
                "raw_hex": build_tcp_packet("10.0.0.1", "10.0.0.2", 1234, 80, seq=1, payload=zip_blob),
            }
        ]
        analysis = self.service.analyze_flow(rows, anchor_src="10.0.0.1", anchor_sport=1234)
        objects = [row for row in analysis["objects"] if row["object_type"] == "zip"]
        self.assertTrue(objects)
        self.assertGreater(objects[0]["size"], 0)

    def test_render_stream_text_split(self) -> None:
        rows = [
            {
                "id": 1,
                "ts": "2024-01-01 00:00:01",
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "src_port": 1234,
                "dst_port": 80,
                "proto": "TCP",
                "raw_hex": build_tcp_packet("10.0.0.1", "10.0.0.2", 1234, 80, seq=1, payload=b"client"),
            },
            {
                "id": 2,
                "ts": "2024-01-01 00:00:02",
                "src_ip": "10.0.0.2",
                "dst_ip": "10.0.0.1",
                "src_port": 80,
                "dst_port": 1234,
                "proto": "TCP",
                "raw_hex": build_tcp_packet("10.0.0.2", "10.0.0.1", 80, 1234, seq=1, payload=b"server"),
            },
        ]
        analysis = self.service.analyze_flow(rows, anchor_src="10.0.0.1", anchor_sport=1234)
        rendered = self.service.render_stream_text(analysis, mode="ascii", direction_mode="split")
        self.assertIn("[C->S Reassembled]", rendered)
        self.assertIn("client", rendered)
        self.assertIn("server", rendered)

    def test_render_stream_text_direction_variants(self) -> None:
        rows = [
            {
                "id": 1,
                "ts": "2024-01-01 00:00:01",
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "src_port": 1234,
                "dst_port": 80,
                "proto": "TCP",
                "raw_hex": build_tcp_packet("10.0.0.1", "10.0.0.2", 1234, 80, seq=1, payload=b"one"),
            },
            {
                "id": 2,
                "ts": "2024-01-01 00:00:02",
                "src_ip": "10.0.0.2",
                "dst_ip": "10.0.0.1",
                "src_port": 80,
                "dst_port": 1234,
                "proto": "TCP",
                "raw_hex": build_tcp_packet("10.0.0.2", "10.0.0.1", 80, 1234, seq=1, payload=b"two"),
            },
        ]
        analysis = self.service.analyze_flow(rows, anchor_src="10.0.0.1", anchor_sport=1234)
        self.assertIn("one", self.service.render_stream_text(analysis, "ascii", "client_to_server"))
        self.assertIn("two", self.service.render_stream_text(analysis, "ascii", "server_to_client"))
        self.assertIn("[0001]", self.service.render_stream_text(analysis, "ascii", "interleaved"))

    def test_collect_segments_supports_udp_without_ethernet(self) -> None:
        rows = [
            {
                "id": 1,
                "ts": "2024-01-01 00:00:01",
                "src_ip": "1.1.1.1",
                "dst_ip": "2.2.2.2",
                "src_port": 53,
                "dst_port": 53000,
                "proto": "UDP",
                "raw_hex": build_udp_packet("1.1.1.1", "2.2.2.2", 53, 53000, b"dns", include_ethernet=False),
            }
        ]
        analysis = self.service.analyze_flow(rows, anchor_src="1.1.1.1", anchor_sport=53)
        self.assertEqual(analysis["client_to_server"]["payload_bytes"], b"dns")

    def test_preview_bytes_truncates_long_content(self) -> None:
        preview = self.service._preview_bytes(b"A" * 300)
        self.assertTrue(preview.endswith("..."))

    def test_project_alphabet_filters_noise(self) -> None:
        projected = self.service._project_alphabet(b"\x00M\x01M\xffYW!!", "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=")
        self.assertEqual(projected, "MMYW")

    def test_export_candidates_csv(self) -> None:
        analysis = {
            "candidates": [
                {
                    "encoding": "base32",
                    "value": "MMYWMX3G",
                    "decoded_text": "demo",
                    "source_kind": "fragmented",
                    "direction": "C->S",
                    "packet_ids": (1, 2),
                    "confidence": "high",
                }
            ],
            "segments": [],
            "client_to_server": {"payload_bytes": b""},
            "server_to_client": {"payload_bytes": b""},
            "interleaved": {"payload_bytes": b""},
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            out = Path(temp_dir) / "candidates.csv"
            self.service.export_flow_artifact(analysis, out, artifact="candidates", file_format="csv")
            with out.open("r", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
        self.assertEqual(rows[0]["encoding"], "base32")
        self.assertEqual(rows[0]["decoded_text"], "demo")

    def test_export_candidates_json_and_txt(self) -> None:
        analysis = {
            "candidates": [
                {
                    "encoding": "base64",
                    "value": "ZmxhZw==",
                    "decoded_text": "flag",
                    "source_kind": "reassembled",
                    "direction": "C->S",
                    "packet_ids": (),
                    "confidence": "medium",
                }
            ],
            "segments": [],
            "client_to_server": {"payload_bytes": b""},
            "server_to_client": {"payload_bytes": b""},
            "interleaved": {"payload_bytes": b""},
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            json_out = Path(temp_dir) / "candidates.json"
            txt_out = Path(temp_dir) / "candidates.txt"
            self.service.export_flow_artifact(analysis, json_out, artifact="candidates", file_format="json")
            self.service.export_flow_artifact(analysis, txt_out, artifact="candidates", file_format="txt")
            payload = json.loads(json_out.read_text(encoding="utf-8"))
            text = txt_out.read_text(encoding="utf-8")
        self.assertEqual(payload[0]["encoding"], "base64")
        self.assertIn("flag", text)

    def test_export_assets_json_and_csv(self) -> None:
        analysis = {
            "candidates": [],
            "assets": [
                {
                    "asset_type": "url",
                    "name": "URL",
                    "value": "https://ctf.local/demo",
                    "direction": "C->S",
                    "source_kind": "reassembled",
                    "packet_ids": (),
                    "confidence": "medium",
                }
            ],
            "objects": [],
            "segments": [],
            "client_to_server": {"payload_bytes": b""},
            "server_to_client": {"payload_bytes": b""},
            "interleaved": {"payload_bytes": b""},
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            json_out = Path(temp_dir) / "assets.json"
            csv_out = Path(temp_dir) / "assets.csv"
            self.service.export_flow_artifact(analysis, json_out, artifact="assets", file_format="json")
            self.service.export_flow_artifact(analysis, csv_out, artifact="assets", file_format="csv")
            payload = json.loads(json_out.read_text(encoding="utf-8"))
            with csv_out.open("r", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
        self.assertEqual(payload[0]["asset_type"], "url")
        self.assertEqual(rows[0]["value"], "https://ctf.local/demo")

    def test_export_objects_json_and_txt(self) -> None:
        analysis = {
            "candidates": [],
            "assets": [],
            "objects": [
                {
                    "object_type": "png",
                    "direction": "C->S",
                    "source_kind": "reassembled",
                    "offset": 12,
                    "size": 24,
                    "preview": "PNG...",
                    "packet_ids": (1,),
                    "data_base64": base64.b64encode(b"png-bytes").decode("ascii"),
                }
            ],
            "segments": [],
            "client_to_server": {"payload_bytes": b""},
            "server_to_client": {"payload_bytes": b""},
            "interleaved": {"payload_bytes": b""},
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            json_out = Path(temp_dir) / "objects.json"
            txt_out = Path(temp_dir) / "objects.txt"
            self.service.export_flow_artifact(analysis, json_out, artifact="objects", file_format="json")
            self.service.export_flow_artifact(analysis, txt_out, artifact="objects", file_format="txt")
            payload = json.loads(json_out.read_text(encoding="utf-8"))
            text = txt_out.read_text(encoding="utf-8")
        self.assertEqual(payload[0]["object_type"], "png")
        self.assertIn("offset=12", text)

    def test_export_carved_object_binary(self) -> None:
        object_row = {
            "object_type": "png",
            "data_base64": base64.b64encode(b"binary-object").decode("ascii"),
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            out = Path(temp_dir) / "obj.bin"
            self.service.export_carved_object(object_row, out)
            payload = out.read_bytes()
        self.assertEqual(payload, b"binary-object")

    def test_export_interleaved_bin(self) -> None:
        analysis = {
            "candidates": [],
            "segments": [],
            "client_to_server": {"payload_bytes": b""},
            "server_to_client": {"payload_bytes": b""},
            "interleaved": {"payload_bytes": b"abc123"},
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            out = Path(temp_dir) / "stream.bin"
            self.service.export_flow_artifact(analysis, out, artifact="interleaved", file_format="bin")
            data = out.read_bytes()
        self.assertEqual(data, b"abc123")

    def test_export_payload_json_base64_and_txt(self) -> None:
        analysis = {
            "candidates": [],
            "segments": [],
            "client_to_server": {"payload_bytes": b"client"},
            "server_to_client": {"payload_bytes": b"server"},
            "interleaved": {"payload_bytes": b"joined"},
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            json_out = Path(temp_dir) / "stream.json"
            b64_out = Path(temp_dir) / "stream.base64"
            txt_out = Path(temp_dir) / "stream.txt"
            self.service.export_flow_artifact(analysis, json_out, artifact="interleaved", file_format="json")
            self.service.export_flow_artifact(analysis, b64_out, artifact="interleaved", file_format="base64")
            self.service.export_flow_artifact(analysis, txt_out, artifact="client_to_server", file_format="txt")
            json_payload = json.loads(json_out.read_text(encoding="utf-8"))
            b64_payload = b64_out.read_text(encoding="utf-8")
            txt_payload = txt_out.read_text(encoding="utf-8")
        self.assertEqual(json_payload["hex"], b"joined".hex())
        self.assertEqual(base64.b64decode(b64_payload), b"joined")
        self.assertIn("client", txt_payload)

    def test_export_segments_json(self) -> None:
        analysis = {
            "candidates": [],
            "segments": [
                {
                    "packet_id": 1,
                    "ts": "2024-01-01 00:00:01",
                    "direction": "C->S",
                    "src_ip": "1.1.1.1",
                    "src_port": 11,
                    "dst_ip": "2.2.2.2",
                    "dst_port": 22,
                    "proto": "TCP",
                    "payload_hex": "414243",
                }
            ],
            "client_to_server": {"payload_bytes": b""},
            "server_to_client": {"payload_bytes": b""},
            "interleaved": {"payload_bytes": b""},
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            out = Path(temp_dir) / "segments.json"
            self.service.export_flow_artifact(analysis, out, artifact="segments", file_format="json")
            payload = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(payload[0]["payload_hex"], "414243")

    def test_export_segments_csv_and_txt(self) -> None:
        analysis = {
            "candidates": [],
            "segments": [
                {
                    "packet_id": 1,
                    "ts": "2024-01-01 00:00:01",
                    "direction": "C->S",
                    "src_ip": "1.1.1.1",
                    "src_port": 11,
                    "dst_ip": "2.2.2.2",
                    "dst_port": 22,
                    "proto": "TCP",
                    "payload_hex": "4142",
                }
            ],
            "client_to_server": {"payload_bytes": b""},
            "server_to_client": {"payload_bytes": b""},
            "interleaved": {"payload_bytes": b""},
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_out = Path(temp_dir) / "segments.csv"
            txt_out = Path(temp_dir) / "segments.txt"
            self.service.export_flow_artifact(analysis, csv_out, artifact="segments", file_format="csv")
            self.service.export_flow_artifact(analysis, txt_out, artifact="segments", file_format="txt")
            with csv_out.open("r", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            text = txt_out.read_text(encoding="utf-8")
        self.assertEqual(rows[0]["payload_hex"], "4142")
        self.assertIn("4142", text)

    def test_invalid_candidate_and_fragment_flush(self) -> None:
        self.assertIsNone(self.service._decode_candidate("%%%INVALID%%%", "base64"))
        self.assertEqual(self.service._flush_fragmented_base32(["MM"], [1], "C->S"), [])


if __name__ == "__main__":
    unittest.main()
