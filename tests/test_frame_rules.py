from __future__ import annotations

import unittest

from src.app.packet_queries import query_offline_frames_page
from src.core.filtering import match_frame_rule


class _FakeOfflinePacketStore:
    def __init__(self, rows: list[dict]) -> None:
        self.rows = list(rows)

    def count_frames(self, source: str = "offline", search_text: str = "", linktype: int = 0) -> int:
        return len(self._filter_base(source=source, search_text=search_text, linktype=linktype))

    def query_frames(
        self,
        limit: int | None,
        offset: int = 0,
        source: str = "offline",
        search_text: str = "",
        linktype: int = 0,
    ) -> list[dict]:
        rows = self._filter_base(source=source, search_text=search_text, linktype=linktype)
        if limit is None or int(limit) <= 0:
            return rows[max(0, int(offset)) :]
        start = max(0, int(offset))
        end = start + int(limit)
        return rows[start:end]

    def _filter_base(self, source: str, search_text: str, linktype: int) -> list[dict]:
        out = []
        needle = str(search_text or "").lower().strip()
        for row in self.rows:
            if source and str(row.get("source", "")) != source:
                continue
            if int(linktype or 0) > 0 and int(row.get("linktype", 0) or 0) != int(linktype):
                continue
            if needle:
                blob = " ".join(
                    [
                        str(row.get("summary", "")),
                        str(row.get("raw_hex", "")),
                        str(row.get("iface", "")),
                        str(row.get("frame_type", "")),
                    ]
                ).lower()
                if needle not in blob:
                    continue
            out.append(dict(row))
        return out


class _FakeRuntime:
    def __init__(self, rows: list[dict]) -> None:
        self.offline_packet_store = _FakeOfflinePacketStore(rows)
        self._packet_query_chunk_size = 2

    def _offline_store_enabled(self) -> bool:
        return True

    @staticmethod
    def _normalize_packet_rows(rows: list[dict]) -> list[dict]:
        return list(rows)


class FrameRuleTests(unittest.TestCase):
    def test_match_frame_rule_supports_numeric_compare_and_contains(self) -> None:
        row = {
            "frame_no": 12,
            "linktype": 249,
            "iface": "usbmon0",
            "frame_type": "linktype-249",
            "caplen": 96,
            "wirelen": 128,
            "summary": "usb transfer setup",
            "raw_hex": "504b0304",
            "source": "offline",
        }

        self.assertTrue(match_frame_rule(row, "linktype == 249"))
        self.assertTrue(match_frame_rule(row, "summary contains usb && wirelen >= 128"))
        self.assertTrue(match_frame_rule(row, "raw_hex contains 504b"))
        self.assertFalse(match_frame_rule(row, "wirelen > 256"))

    def test_query_offline_frames_page_applies_rule_expr(self) -> None:
        rows = [
            {
                "id": 1,
                "frame_no": 1,
                "ts": 1.0,
                "linktype": 1,
                "iface": "eth0",
                "frame_type": "ethernet",
                "caplen": 64,
                "wirelen": 64,
                "summary": "ethernet frame",
                "raw_hex": "0011",
                "source": "offline",
            },
            {
                "id": 2,
                "frame_no": 2,
                "ts": 2.0,
                "linktype": 249,
                "iface": "usbmon0",
                "frame_type": "linktype-249",
                "caplen": 72,
                "wirelen": 80,
                "summary": "usb transfer bulk",
                "raw_hex": "504b0304",
                "source": "offline",
            },
        ]
        runtime = _FakeRuntime(rows)

        result = query_offline_frames_page(
            runtime,
            page=1,
            page_size=50,
            search_text="",
            rule_expr="linktype == 249 && summary contains usb",
        )

        self.assertEqual(result["total"], 1)
        self.assertEqual(len(result["rows"]), 1)
        self.assertEqual(result["rows"][0]["frame_no"], 2)


if __name__ == "__main__":
    unittest.main()
