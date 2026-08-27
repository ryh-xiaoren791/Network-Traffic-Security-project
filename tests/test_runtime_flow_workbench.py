from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from src.app.runtime import AppRuntime
from src.core.storage.offline_packet_store import OfflinePacketStore


class RuntimeFlowWorkbenchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.runtime = AppRuntime.__new__(AppRuntime)
        self.runtime.flow_workbench = Mock()

    def test_analyze_flow_delegates_to_service(self) -> None:
        rows = [
            {
                "id": 100,
                "src_ip": "10.0.0.1",
                "src_port": 1234,
                "dst_ip": "10.0.0.2",
                "dst_port": 80,
                "proto": "TCP",
                "raw_hex": "00",
            }
        ]
        self.runtime.query_flow_packets = Mock(return_value=rows)
        self.runtime.flow_workbench.analyze_flow.return_value = {"segment_count": 1}

        result = AppRuntime.analyze_flow(self.runtime, packet_id=100, limit=200)

        self.assertEqual(result["segment_count"], 1)
        self.runtime.query_flow_packets.assert_called_once_with(packet_id=100, limit=200)
        self.runtime.flow_workbench.analyze_flow.assert_called_once()

    def test_render_flow_stream_text_delegates_to_service(self) -> None:
        self.runtime.flow_workbench.render_stream_text.return_value = "stream-content"

        rendered = AppRuntime.render_flow_stream_text(self.runtime, analysis={"a": 1}, mode="ascii", direction_mode="split")

        self.assertEqual(rendered, "stream-content")
        self.runtime.flow_workbench.render_stream_text.assert_called_once()

    def test_export_flow_artifact_delegates_to_service(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            out_path = Path(temp_dir) / "out.txt"
            self.runtime.flow_workbench.export_flow_artifact.return_value = out_path

            result = AppRuntime.export_flow_artifact(
                self.runtime,
                analysis={"a": 1},
                output_path=out_path,
                artifact="candidates",
                file_format="json",
            )

        self.assertEqual(result, out_path)
        self.runtime.flow_workbench.export_flow_artifact.assert_called_once()

    def test_export_carved_object_delegates_to_service(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            out_path = Path(temp_dir) / "obj.bin"
            self.runtime.flow_workbench.export_carved_object.return_value = out_path

            result = AppRuntime.export_carved_object(
                self.runtime,
                object_row={"object_type": "png"},
                output_path=out_path,
            )

        self.assertEqual(result, out_path)
        self.runtime.flow_workbench.export_carved_object.assert_called_once()

    def test_expand_packet_rows_merges_base_fields(self) -> None:
        self.runtime.query_packet_details = Mock(
            return_value={
                1: {
                    "id": 1,
                    "ts": "2024-01-01 00:00:01",
                    "src_ip": "1.1.1.1",
                    "src_port": 1,
                    "dst_ip": "2.2.2.2",
                    "dst_port": 2,
                    "proto": "TCP",
                    "raw_hex": "0011",
                }
            }
        )
        rows = [{"id": 1, "risk_level": "medium", "source": "offline"}]

        expanded = AppRuntime.expand_packet_rows(self.runtime, rows, detail_batch_size=100)

        self.assertEqual(expanded[0]["risk_level"], "medium")
        self.assertEqual(expanded[0]["source"], "offline")

    def test_extract_packet_fields_delegates_to_batch_service(self) -> None:
        self.runtime.packet_batch_export = Mock()
        self.runtime.expand_packet_rows = Mock(return_value=[{"id": 1, "raw_hex": "00"}])
        self.runtime.packet_batch_export.extract_field_rows.return_value = [{"id": 1, "app_protocol": "HTTP"}]

        rows = AppRuntime.extract_packet_fields(self.runtime, [{"id": 1}])

        self.assertEqual(rows[0]["app_protocol"], "HTTP")
        self.runtime.packet_batch_export.extract_field_rows.assert_called_once()

    def test_export_packet_fields_delegates_to_batch_service(self) -> None:
        self.runtime.packet_batch_export = Mock()
        with tempfile.TemporaryDirectory() as temp_dir:
            out_path = Path(temp_dir) / "fields.csv"
            self.runtime.packet_batch_export.export_field_rows.return_value = out_path

            result = AppRuntime.export_packet_fields(self.runtime, [{"id": 1}], out_path, "csv")

        self.assertEqual(result, out_path)
        self.runtime.packet_batch_export.export_field_rows.assert_called_once()

    def test_extract_packet_flows_delegates_to_batch_service(self) -> None:
        self.runtime.packet_batch_export = Mock()
        self.runtime.expand_packet_rows = Mock(return_value=[{"id": 1, "raw_hex": "00"}])
        self.runtime.packet_batch_export.extract_flow_rows.return_value = [{"flow_index": 1}]

        rows = AppRuntime.extract_packet_flows(self.runtime, [{"id": 1}])

        self.assertEqual(rows[0]["flow_index"], 1)
        self.runtime.packet_batch_export.extract_flow_rows.assert_called_once()

    def test_export_packet_flows_delegates_to_batch_service(self) -> None:
        self.runtime.packet_batch_export = Mock()
        with tempfile.TemporaryDirectory() as temp_dir:
            out_path = Path(temp_dir) / "flows.csv"
            self.runtime.packet_batch_export.export_flow_rows.return_value = out_path

            result = AppRuntime.export_packet_flows(self.runtime, [{"flow_index": 1}], out_path, "csv")

        self.assertEqual(result, out_path)
        self.runtime.packet_batch_export.export_flow_rows.assert_called_once()

    def test_extract_packet_candidates_delegates_to_batch_service(self) -> None:
        self.runtime.packet_batch_export = Mock()
        self.runtime.expand_packet_rows = Mock(return_value=[{"id": 1, "raw_hex": "00"}])
        self.runtime.packet_batch_export.extract_candidate_rows.return_value = [{"encoding": "base32"}]

        rows = AppRuntime.extract_packet_candidates(self.runtime, [{"id": 1}])

        self.assertEqual(rows[0]["encoding"], "base32")
        self.runtime.packet_batch_export.extract_candidate_rows.assert_called_once()

    def test_export_packet_candidates_delegates_to_batch_service(self) -> None:
        self.runtime.packet_batch_export = Mock()
        with tempfile.TemporaryDirectory() as temp_dir:
            out_path = Path(temp_dir) / "candidates.csv"
            self.runtime.packet_batch_export.export_candidate_rows.return_value = out_path

            result = AppRuntime.export_packet_candidates(self.runtime, [{"encoding": "base32"}], out_path, "csv")

        self.assertEqual(result, out_path)
        self.runtime.packet_batch_export.export_candidate_rows.assert_called_once()

    def test_export_packet_flow_body_bundle_delegates_to_batch_service(self) -> None:
        self.runtime.packet_batch_export = Mock()
        self.runtime.expand_packet_rows = Mock(return_value=[{"id": 1, "raw_hex": "00"}])
        with tempfile.TemporaryDirectory() as temp_dir:
            out_path = Path(temp_dir) / "bundle"
            self.runtime.packet_batch_export.export_flow_body_bundle.return_value = out_path

            result = AppRuntime.export_packet_flow_body_bundle(self.runtime, [{"id": 1}], out_path)

        self.assertEqual(result, out_path)
        self.runtime.packet_batch_export.export_flow_body_bundle.assert_called_once()

    def test_query_packets_filtered_pushdown_path(self) -> None:
        self.runtime._packet_query_chunk_size = 1000
        self.runtime._normalize_packet_sort_key = Mock(return_value="ts")
        self.runtime._build_packet_rule_sql = Mock(return_value=("", []))
        self.runtime._count_packet_rows = Mock(return_value=150)
        self.runtime._query_packet_rows_chunk = Mock(return_value=[{"id": index} for index in range(1, 101)])
        self.runtime._attach_packet_risk = Mock(side_effect=lambda rows: rows)

        result = AppRuntime.query_packets_filtered(self.runtime, max_rows=100)

        self.assertEqual(result["total"], 150)
        self.assertEqual(len(result["rows"]), 100)
        self.assertTrue(result["truncated"])
        self.runtime._query_packet_rows_chunk.assert_called_once()
        self.runtime._count_packet_rows.assert_called_once()

    def test_query_packets_filtered_pushdown_skips_count_when_rows_do_not_hit_limit(self) -> None:
        self.runtime._packet_query_chunk_size = 1000
        self.runtime._normalize_packet_sort_key = Mock(return_value="ts")
        self.runtime._build_packet_rule_sql = Mock(return_value=("", []))
        self.runtime._count_packet_rows = Mock(side_effect=AssertionError("count should be skipped"))
        self.runtime._query_packet_rows_chunk = Mock(return_value=[{"id": 1}, {"id": 2}])
        self.runtime._attach_packet_risk = Mock(side_effect=lambda rows: rows)

        result = AppRuntime.query_packets_filtered(self.runtime, max_rows=100)

        self.assertEqual(result["total"], 2)
        self.assertFalse(result["truncated"])
        self.runtime._count_packet_rows.assert_not_called()

    def test_query_packets_page_pushdown_skips_count_when_first_page_not_full(self) -> None:
        self.runtime._normalize_packet_sort_key = Mock(return_value="ts")
        self.runtime._build_packet_rule_sql = Mock(return_value=("", []))
        self.runtime._count_packet_rows = Mock(side_effect=AssertionError("count should be skipped"))
        self.runtime._query_packet_rows_chunk = Mock(return_value=[{"id": 1}, {"id": 2}])
        self.runtime._attach_packet_risk = Mock(side_effect=lambda rows: rows)

        result = AppRuntime.query_packets_page(self.runtime, page=1, page_size=100)

        self.assertEqual(result["total"], 2)
        self.assertEqual(result["page"], 1)
        self.assertEqual(result["total_pages"], 1)
        self.runtime._count_packet_rows.assert_not_called()

    def test_query_flow_packets_live_uses_single_query_path(self) -> None:
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.execute(
            """
            CREATE TABLE captured_packets (
                id INTEGER PRIMARY KEY,
                ts REAL,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                proto TEXT,
                length INTEGER,
                process_name TEXT,
                raw_hex TEXT,
                source TEXT
            )
            """
        )
        conn.executemany(
            """
            INSERT INTO captured_packets (id, ts, src_ip, dst_ip, src_port, dst_port, proto, length, process_name, raw_hex, source)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (1, 1.0, "10.0.0.1", "10.0.0.2", 1234, 80, "TCP", 100, "proc-a", "aa", "live"),
                (2, 2.0, "10.0.0.2", "10.0.0.1", 80, 1234, "TCP", 200, "proc-b", "bb", "live"),
                (3, 3.0, "10.0.0.3", "10.0.0.4", 9000, 443, "TCP", 300, "proc-c", "cc", "live"),
            ],
        )
        self.runtime.db = Mock(conn=conn)
        self.runtime._offline_store_enabled = Mock(return_value=False)
        self.runtime._parse_ts_float = Mock(side_effect=lambda value: float(value))
        self.runtime._render_ts_text = Mock(side_effect=lambda value: f"ts={value}")
        self.runtime.query_packet_detail = Mock(side_effect=AssertionError("query_packet_detail should not be used"))

        rows = AppRuntime.query_flow_packets(self.runtime, packet_id=1, limit=10)

        self.assertEqual([row["id"] for row in rows], [1, 2])
        self.assertEqual(rows[0]["ts"], "ts=1.0")
        self.assertEqual(rows[1]["ts_epoch"], 2.0)
        self.runtime.query_packet_detail.assert_not_called()

    def test_offline_store_query_flow_packets_uses_seed_query(self) -> None:
        store = OfflinePacketStore.__new__(OfflinePacketStore)
        store.conn = sqlite3.connect(":memory:")
        store.conn.execute(
            """
            CREATE TABLE offline_packets (
                id INTEGER PRIMARY KEY,
                ts REAL,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                proto TEXT,
                length INTEGER,
                process_name TEXT,
                raw_hex TEXT,
                source TEXT
            )
            """
        )
        store.conn.executemany(
            """
            INSERT INTO offline_packets (id, ts, src_ip, dst_ip, src_port, dst_port, proto, length, process_name, raw_hex, source)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (1, 1.0, "10.0.0.1", "10.0.0.2", 1234, 80, "TCP", 100, "proc-a", "aa", "offline"),
                (2, 2.0, "10.0.0.2", "10.0.0.1", 80, 1234, "TCP", 200, "proc-b", "bb", "offline"),
                (3, 3.0, "10.0.0.1", "10.0.0.2", 1234, 80, "TCP", 300, "proc-c", "cc", "other"),
            ],
        )

        encoded_seed_id = OfflinePacketStore._encode_id(1)
        rows = OfflinePacketStore.query_flow_packets(store, encoded_seed_id, limit=10)

        self.assertEqual([row["id"] for row in rows], [OfflinePacketStore._encode_id(1), OfflinePacketStore._encode_id(2)])


if __name__ == "__main__":
    unittest.main()
