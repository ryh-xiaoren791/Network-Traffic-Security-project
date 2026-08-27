from __future__ import annotations

import unittest

from src.core.ctf.batch_export import PacketBatchExportService


def _build_fake_analysis(client_payload: bytes, server_payload: bytes) -> tuple[dict, list[dict], dict]:
    return (
        {
            "source": "offline",
            "proto": "TCP",
            "endpoint_a": "192.168.1.10:40000",
            "endpoint_b": "192.168.1.20:80",
        },
        [{"id": 1}, {"id": 2}],
        {
            "client_to_server": {"payload_bytes": client_payload},
            "server_to_client": {"payload_bytes": server_payload},
            "candidates": [],
            "assets": [],
            "objects": [],
            "segment_count": 0,
        },
    )


class HttpBatchExportTests(unittest.TestCase):
    def test_extract_http_interaction_rows(self) -> None:
        service = PacketBatchExportService()
        req = (
            b"GET /ctf/Less-5/?id=1%27%20and%20ascii(substr((select%20flag),1,1))=102 HTTP/1.1\r\n"
            b"Host: test.local\r\n"
            b"User-Agent: unit-test\r\n"
            b"\r\n"
        )
        body_ok = b"You are in" + (b"A" * (978 - len(b"You are in")))
        resp = b"HTTP/1.1 200 OK\r\nContent-Length: 978\r\n\r\n" + body_ok
        fake = _build_fake_analysis(req, resp)
        service._build_flow_analyses = lambda _rows: [fake]  # type: ignore[method-assign]

        rows = service.extract_http_interaction_rows([{}])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["method"], "GET")
        self.assertEqual(rows[0]["response_status"], 200)
        self.assertEqual(rows[0]["response_body_length"], 978)
        self.assertTrue(rows[0]["response_contains_you"])
        self.assertIn("ascii(substr", rows[0]["request_uri_decoded"])

    def test_extract_http_variant_rows_reconstructs_text(self) -> None:
        service = PacketBatchExportService()
        req = (
            b"GET /ctf/Less-5/?id=1%27%20and%20ascii(substr((select%20flag),1,1))=102 HTTP/1.1\r\nHost: test.local\r\n\r\n"
            b"GET /ctf/Less-5/?id=1%27%20and%20ascii(substr((select%20flag),2,1))=108 HTTP/1.1\r\nHost: test.local\r\n\r\n"
        )
        ok1 = b"You are in" + (b"A" * (978 - len(b"You are in")))
        ok2 = b"You are in" + (b"B" * (978 - len(b"You are in")))
        resp = (
            b"HTTP/1.1 200 OK\r\nContent-Length: 978\r\n\r\n"
            + ok1
            + b"HTTP/1.1 200 OK\r\nContent-Length: 978\r\n\r\n"
            + ok2
        )
        fake = _build_fake_analysis(req, resp)
        service._build_flow_analyses = lambda _rows: [fake]  # type: ignore[method-assign]

        rows = service.extract_http_variant_rows([{}])
        summary = [row for row in rows if row.get("row_type") == "summary"]
        self.assertEqual(len(summary), 1)
        self.assertEqual(summary[0]["param_value"], "fl")


if __name__ == "__main__":
    unittest.main()
