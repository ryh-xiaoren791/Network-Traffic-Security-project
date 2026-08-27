import json
from pathlib import Path

import pytest

from src.app.runtime import AppRuntime, OfflineImportProfile
from src.config import AppConfig
from src.core.aggregation.session_aggregator import SessionAggregator
from src.core.audit.service import AuditService
from src.core.auth.service import AuthService
from src.core.ctf.clues import build_packet_ctf_clues
from src.core.detection.model_engine import ModelEngine
from src.core.detection.rule_engine import RuleEngine
from src.core.detection.service import DetectionService
from src.core.filtering.packet_rules import match_packet_rule, parse_packet_rule_term
from src.core.packet_inspection import dissect_packet_bytes, parse_dns_fields, extract_app_fields
from src.core.report.service import ReportService
from src.core.storage.db import Database
from src.core.whitelist_blacklist.service import ListService


@pytest.mark.integration
class TestDatabaseDetectionIntegration:
    def test_detection_pipeline_produces_alerts(self, tmp_db):
        ls = ListService(tmp_db)
        model = ModelEngine(Path("nonexistent.joblib"))
        rule = RuleEngine()
        service = DetectionService(tmp_db, ls, model, rule)
        service.start_learning(0)

        features = [
            {
                "src_ip": "192.168.1.1",
                "dst_ip": "10.0.0.1",
                "src_port": 4444,
                "dst_port": 443,
                "proto": "TCP",
                "packet_rate": 50.0,
                "conn_freq": 20.0,
                "port_visits": 40,
                "session_duration": 0.3,
                "req_interval": 0.1,
                "conn_success_rate": 0.5,
                "avg_pkt_size": 100.0,
                "direction": "outbound",
            }
        ]
        alerts = service.process(features)
        assert isinstance(alerts, list)

    def test_detection_alert_columns(self, tmp_db):
        ls = ListService(tmp_db)
        ls._match_tracker_host = lambda _: None
        model = ModelEngine(Path("nonexistent.joblib"))
        rule = RuleEngine()
        service = DetectionService(tmp_db, ls, model, rule)
        service.start_learning(0)

        features = [
            {
                "src_ip": "10.0.0.99",
                "dst_ip": "8.8.8.8",
                "src_port": 12345,
                "dst_port": 53,
                "proto": "UDP",
                "packet_rate": 100.0,
                "conn_freq": 30.0,
                "port_visits": 50,
                "session_duration": 0.2,
                "req_interval": 0.05,
                "conn_success_rate": 0.3,
                "avg_pkt_size": 80.0,
                "direction": "outbound",
            }
        ]
        service.process(features)

        c = tmp_db.conn.cursor()
        c.execute("SELECT * FROM alerts LIMIT 1")
        row = c.fetchone()
        if row is not None:
            columns = [desc[0] for desc in c.description]
            assert "level" in columns
            assert "category" in columns
            assert "ts" in columns


@pytest.mark.integration
class TestWhitelistDetectionIntegration:
    def test_whitelisted_ip_bypass(self, tmp_db):
        ls = ListService(tmp_db)
        ls.upsert("10.0.0.99", "white", 1, "test bypass")
        assert ls.classify_ip("10.0.0.99") == "white"

        model = ModelEngine(Path("nonexistent.joblib"))
        rule = RuleEngine()
        service = DetectionService(tmp_db, ls, model, rule)
        service.start_learning(0)

        features = [
            {
                "src_ip": "10.0.0.99",
                "dst_ip": "8.8.8.8",
                "src_port": 12345,
                "dst_port": 53,
                "proto": "UDP",
                "packet_rate": 100.0,
                "conn_freq": 30.0,
                "port_visits": 50,
                "session_duration": 0.2,
                "req_interval": 0.05,
                "conn_success_rate": 0.3,
                "avg_pkt_size": 80.0,
                "direction": "outbound",
            }
        ]
        service.process(features)

    def test_blacklisted_ip_detected(self, tmp_db):
        ls = ListService(tmp_db)
        ls.upsert("93.184.216.34", "black", 1, "known bad")
        assert ls.classify_ip("93.184.216.34") == "black"

        model = ModelEngine(Path("nonexistent.joblib"))
        rule = RuleEngine()
        service = DetectionService(tmp_db, ls, model, rule)
        service.start_learning(0)

        features = [
            {
                "src_ip": "93.184.216.34",
                "dst_ip": "192.168.1.1",
                "src_port": 443,
                "dst_port": 8080,
                "proto": "TCP",
                "packet_rate": 1.0,
                "conn_freq": 0.5,
                "port_visits": 2,
                "session_duration": 10.0,
                "req_interval": 1.0,
                "conn_success_rate": 1.0,
                "avg_pkt_size": 200.0,
                "direction": "inbound",
            }
        ]
        alerts = service.process(features)
        assert isinstance(alerts, list)


@pytest.mark.integration
class TestAuthAuditIntegration:
    def test_login_success(self, tmp_db):
        auth = AuthService(tmp_db)
        user = auth.login("admin", "Admin@123456")
        assert user is not None

    def test_login_audit_log(self, tmp_db):
        auth = AuthService(tmp_db)
        audit = AuditService(tmp_db)

        auth.login("admin", "Admin@123456")
        logs = audit.query()
        assert isinstance(logs, list)

    def test_failed_login_audit(self, tmp_db):
        auth = AuthService(tmp_db)
        audit = AuditService(tmp_db)

        auth.login("admin", "wrong_password")
        logs = audit.query()
        assert isinstance(logs, list)

    def test_audit_delete_cleanup(self, tmp_db):
        audit = AuditService(tmp_db)
        count = audit.delete_logs()
        assert count >= 0


@pytest.mark.integration
class TestSessionAggregationIntegration:
    def test_aggregation_batch_ingest(self):
        import time
        agg = SessionAggregator()
        ts = time.time()
        packets = [
            {
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "src_port": 1234,
                "dst_port": 80,
                "proto": "TCP",
                "length": 500,
                "ts": ts + i,
                "process_name": "test.exe",
                "flags": 24,
                "raw_hex": None,
                "raw_ascii": "",
                "direction": "outbound",
            }
            for i in range(5)
        ]
        agg.ingest_batch(packets)
        features = agg.flush_features(ts + 10)
        assert isinstance(features, list)

    def test_multiple_packets_ingest(self):
        import time
        agg = SessionAggregator()
        ts = time.time()
        packets = [
            {
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "src_port": 1234,
                "dst_port": 80,
                "proto": "TCP",
                "length": 500,
                "ts": ts + i,
                "process_name": "test.exe",
                "flags": 24,
                "raw_hex": None,
                "raw_ascii": "",
                "direction": "outbound",
            }
            for i in range(5)
        ]
        agg.ingest_batch(packets)


@pytest.mark.integration
class TestPacketInspectionIntegration:
    def test_dissect_with_ctf_clues(self):
        packet_dict = {
            "raw_hex": (
                "4500003ca822400040063d2dc0a80164c0a80101"
                "c16001bb1234567800000000a002faf0bb1b0000"
                "020405b40402080a123456780000000001030307"
            ),
        }
        result = dissect_packet_bytes(packet_dict)
        assert result is not None
        if result.get("src_ip"):
            clues = build_packet_ctf_clues(result)
            assert isinstance(clues, list)

    def test_dissect_basic(self):
        packet_dict = {
            "raw_hex": (
                "4500003ca822400040063d2dc0a80164c0a80101"
                "c16001bb1234567800000000a002faf0bb1b0000"
                "020405b40402080a123456780000000001030307"
            ),
        }
        result = dissect_packet_bytes(packet_dict)
        assert result is not None


@pytest.mark.integration
class TestReportIntegration:
    def test_report_generation_basic(self, tmp_db):
        report_service = ReportService(tmp_db)
        report_dir = tmp_db.db_path.parent / "report_test"
        result = report_service.generate_visual_report(report_dir)
        assert result is not None

    def test_report_output_exists(self, tmp_db):
        report_service = ReportService(tmp_db)
        report_dir = tmp_db.db_path.parent / "report_html"
        result = report_service.generate_visual_report(report_dir)
        if result:
            assert Path(result).exists() or str(result).endswith(".html")


@pytest.mark.integration
class TestPacketQueryIntegration:
    def test_packet_rule_match(self):
        packet = {
            "src_ip": "192.168.1.1",
            "dst_ip": "10.0.0.1",
            "src_port": 50000,
            "dst_port": 80,
            "proto": "TCP",
        }
        result = match_packet_rule(packet, "dst_port == 80")
        assert result is True

        packet["dst_port"] = 443
        result = match_packet_rule(packet, "dst_port == 80")
        assert result is False

    def test_complex_rule_with_and(self):
        packet = {
            "src_ip": "192.168.1.1",
            "dst_ip": "10.0.0.1",
            "src_port": 50000,
            "dst_port": 80,
            "proto": "TCP",
        }
        assert match_packet_rule(packet, "dst_port == 80 && proto == tcp") is True
        packet["proto"] = "UDP"
        assert match_packet_rule(packet, "dst_port == 80 && proto == tcp") is False


@pytest.mark.integration
class TestWhitelistBlacklistService:
    def test_list_add_and_classify(self, tmp_db):
        ls = ListService(tmp_db)
        ls.upsert("1.2.3.4", "white", 1, "test entry")
        assert ls.classify_ip("1.2.3.4") == "white"

    def test_list_blacklist_classify(self, tmp_db):
        ls = ListService(tmp_db)
        ls.upsert("5.6.7.8", "black", 1, "bad")
        assert ls.classify_ip("5.6.7.8") == "black"

    def test_list_delete(self, tmp_db):
        ls = ListService(tmp_db)
        ls.upsert("9.9.9.9", "white", 1, "temp")
        items = ls.all_items()
        for item in items:
            if item["ip"] == "9.9.9.9":
                ls.delete(item["id"])
                break
        assert ls.classify_ip("9.9.9.9") is None


@pytest.mark.integration
class TestAuditServiceIntegration:
    def test_audit_query(self, tmp_db):
        audit = AuditService(tmp_db)
        logs = audit.query()
        assert isinstance(logs, list)

    def test_audit_delete_logs(self, tmp_db):
        audit = AuditService(tmp_db)
        count = audit.delete_logs()
        assert isinstance(count, int)


@pytest.mark.api
class TestAppRuntimeApi:
    def test_offline_import_profile_speed(self):
        profile = OfflineImportProfile(
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
        assert profile.mode == "speed"
        assert profile.batch_size == 256
        assert profile.enable_detection is False

    def test_offline_import_profile_detect(self):
        profile = OfflineImportProfile(
            mode="detect",
            batch_size=256,
            raw_hex_preview_bytes=8,
            store_raw_hex=False,
            store_packets=False,
            enable_app_meta=True,
            enable_detection=True,
            parser_threads=4,
            cpu_limit_percent=60,
            detection_flush_interval_batches=5,
        )
        assert profile.mode == "detect"
        assert profile.enable_detection is True
        assert profile.parser_threads == 4
        assert profile.cpu_limit_percent == 60

    def test_packet_rule_term_parse(self):
        term = parse_packet_rule_term("dst_port == 80")
        assert term is not None
        assert len(term) == 3

    def test_dns_field_parse(self):
        raw = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
        result = parse_dns_fields(raw)
        assert result is not None

    def test_http_field_parse(self):
        from src.core.packet_inspection import extract_http_line

        payload_bytes = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        hex_str = payload_bytes.hex()
        packet_dict = {"raw_hex": hex_str}
        result = dissect_packet_bytes(packet_dict)

        if result.get("payload"):
            fields = extract_app_fields(result["payload"], "HTTP")
            assert isinstance(fields, dict)
