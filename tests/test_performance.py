import hashlib
import time
from pathlib import Path

import pytest

from src.core.auth.service import AuthService
from src.core.detection.model_engine import ModelEngine
from src.core.detection.rule_engine import RuleEngine
from src.core.storage.db import Database, hash_password, verify_password


@pytest.mark.performance
class TestAuthPerformance:
    def test_hash_password_performance(self):
        t0 = time.perf_counter()
        for _ in range(10):
            hash_password("test_password_123")
        elapsed = time.perf_counter() - t0
        assert elapsed < 5.0, f"password hashing too slow: {elapsed:.2f}s for 10 iterations"

    def test_verify_password_performance(self):
        stored = hash_password("test_password_123")
        t0 = time.perf_counter()
        for _ in range(100):
            verify_password("test_password_123", stored)
        elapsed = time.perf_counter() - t0
        threshold = 15.0
        assert elapsed < threshold, f"password verification: {elapsed:.2f}s for 100 iterations (threshold {threshold}s)"

    def test_auth_login_performance(self, tmp_db):
        t0 = time.perf_counter()
        for _ in range(20):
            auth = AuthService(tmp_db)
            auth.login("admin", "admin123")
        elapsed = time.perf_counter() - t0
        threshold = 3.0
        assert elapsed < threshold, f"login too slow: {elapsed:.2f}s for 20 iterations (threshold {threshold}s)"


@pytest.mark.performance
class TestRuleEnginePerformance:
    def test_rule_engine_bulk_detect(self):
        engine = RuleEngine()
        features = {
            "packet_rate": 50.0,
            "port_visits": 20,
            "session_duration": 0.5,
            "conn_freq": 15.0,
        }
        t0 = time.perf_counter()
        for _ in range(1000):
            engine.detect(features)
        elapsed = time.perf_counter() - t0
        assert elapsed < 1.0, f"rule engine too slow: {elapsed:.3f}s for 1000 detections"


@pytest.mark.performance
class TestDatabasePerformance:
    def test_db_insert_bulk(self, tmp_db):
        c = tmp_db.conn.cursor()
        t0 = time.perf_counter()
        c.execute("BEGIN")
        for i in range(500):
            c.execute(
                "INSERT INTO alerts (ts, level, category, src_ip, dst_ip, reason) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                ("2026-01-01 12:00:00", "high", "scan", f"10.0.0.{i}", "10.0.0.1", "test"),
            )
        c.execute("COMMIT")
        elapsed = time.perf_counter() - t0
        assert elapsed < 2.0, f"bulk insert too slow: {elapsed:.3f}s for 500 rows"

    def test_db_query_performance(self, tmp_db):
        c = tmp_db.conn.cursor()
        c.execute("BEGIN")
        for i in range(500):
            c.execute(
                "INSERT INTO alerts (ts, level, category, src_ip, dst_ip, reason) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                ("2026-01-01 12:00:00", "high", "scan", f"10.0.0.{i}", "10.0.0.1", "test"),
            )
        c.execute("COMMIT")

        t0 = time.perf_counter()
        for _ in range(100):
            c.execute("SELECT * FROM alerts WHERE level=?", ("high",))
            c.fetchall()
        elapsed = time.perf_counter() - t0
        assert elapsed < 1.0, f"query too slow: {elapsed:.3f}s for 100 queries"


@pytest.mark.performance
class TestHashPerformance:
    def test_hash_deterministic_ip_encoding(self):
        from src.core.detection.service import DetectionService

        ip = "192.168.1.100"
        t0 = time.perf_counter()
        for _ in range(10000):
            DetectionService._ip_to_bucket(ip)
        elapsed = time.perf_counter() - t0
        assert elapsed < 0.5, f"IP bucket too slow: {elapsed:.3f}s for 10000 encodes"


@pytest.mark.performance
class TestSessionAggregatorPerformance:
    def test_aggregator_bulk_packets(self):
        import time as _time
        from src.core.aggregation.session_aggregator import SessionAggregator

        agg = SessionAggregator()
        ts = _time.time()

        t0 = time.perf_counter()
        packets = [
            {
                "src_ip": "10.0.0.1",
                "dst_ip": f"10.0.0.{100 + i}",
                "src_port": 1234,
                "dst_port": 80,
                "proto": "TCP",
                "length": 500,
                "ts": ts + i * 0.1,
                "process_name": "test.exe",
                "flags": 24,
                "raw_hex": None,
                "raw_ascii": "",
                "direction": "outbound",
            }
            for i in range(200)
        ]
        agg.ingest_batch(packets)
        elapsed = time.perf_counter() - t0
        assert elapsed < 3.0, f"aggregator too slow: {elapsed:.3f}s for 200 packets"


@pytest.mark.performance
class TestPacketInspectionPerformance:
    def test_dissect_raw_hex(self):
        from src.core.packet_inspection import dissect_packet_bytes

        raw_hex = (
            "4500003ca822400040063d2dc0a80164c0a80101"
            "c16001bb1234567800000000a002faf0bb1b0000"
            "020405b40402080a123456780000000001030307"
        )
        packet_dict = {"raw_hex": raw_hex}
        t0 = time.perf_counter()
        for _ in range(500):
            dissect_packet_bytes(packet_dict)
        elapsed = time.perf_counter() - t0
        assert elapsed < 2.0, f"packet dissection too slow: {elapsed:.3f}s for 500 packets"


@pytest.mark.performance
class TestCTFServicePerformance:
    def test_decode_payload_performance(self):
        from src.core.ctf.service import FlowWorkbenchService

        svc = FlowWorkbenchService.__new__(FlowWorkbenchService)
        payload = b"SGVsbG8gV29ybGQhIFRlc3QgcGF5bG9hZCBkYXRhIGZvciBwZXJmb3JtYW5jZS4="

        t0 = time.perf_counter()
        for _ in range(500):
            svc.decode_payload_by_mode(payload, "base64")
        elapsed = time.perf_counter() - t0
        assert elapsed < 2.0, f"payload decode too slow: {elapsed:.3f}s for 500 decodes"


@pytest.mark.performance
class TestOfflineImportProfile:
    def test_profile_dataclass_instantiation(self):
        from src.app.runtime import OfflineImportProfile

        t0 = time.perf_counter()
        for _ in range(10000):
            OfflineImportProfile(
                mode="speed",
                batch_size=256,
                raw_hex_preview_bytes=4,
                store_raw_hex=False,
                store_packets=False,
                enable_app_meta=False,
                enable_detection=False,
                parser_threads=2,
                cpu_limit_percent=0,
                detection_flush_interval_batches=10,
            )
        elapsed = time.perf_counter() - t0
        assert elapsed < 1.0, f"profile creation too slow: {elapsed:.3f}s for 10000 instances"
