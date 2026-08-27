import ipaddress
import queue
import socket
from pathlib import Path

from src.core.detection.model_engine import ModelEngine
from src.core.detection.rule_engine import RuleEngine
from src.core.auth.service import AuthService
from src.core.aggregation.session_aggregator import SessionAggregator
from src.core.capture.capture_engine import CaptureEngine, CaptureConfig
from src.core.notify.service import NotificationService
from src.core.report.service import ReportService
from src.core.storage.db import Database
from src.core.whitelist_blacklist.service import ListService
from src.core.detection.service import DetectionService, IP_BUCKETS
from src.app.runtime import AppRuntime


def test_db_init(tmp_path: Path):
    db = Database(tmp_path / "t.db")
    c = db.conn.cursor()
    c.execute("SELECT username FROM users WHERE username='admin'")
    assert c.fetchone() is not None


def test_rule_engine():
    r = RuleEngine()
    f = {
        "packet_rate": 999,
        "port_visits": 40,
        "session_duration": 0.3,
        "conn_freq": 10,
    }
    out = r.detect(f)
    assert out["matched"] is True
    assert out["level"] == "high"


def test_rule_engine_loopback_downgrades_high_risk():
    r = RuleEngine()
    f = {
        "src_ip": "127.0.0.1",
        "dst_ip": "127.0.0.1",
        "packet_rate": 999,
        "port_visits": 40,
        "session_duration": 0.2,
        "conn_freq": 10,
    }
    out = r.detect(f)
    assert out["matched"] is True
    assert out["level"] == "medium"
    assert out["category"] == "本机回环通信"


def test_detection_pipeline(tmp_path: Path):
    db = Database(tmp_path / "t2.db")
    ls = ListService(db)
    model = ModelEngine(tmp_path / "m.joblib")
    rule = RuleEngine()
    service = DetectionService(db, ls, model, rule)
    service.start_learning(0)
    feats = [
        {
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "src_port": 1234,
            "dst_port": 80,
            "proto": "TCP",
            "packet_rate": 2.0,
            "conn_freq": 1.0,
            "port_visits": 3,
            "session_duration": 5.0,
            "req_interval": 0.2,
            "conn_success_rate": 1.0,
            "avg_pkt_size": 120.0,
            "direction": "inbound",
        }
    ]
    alerts = service.process(feats)
    assert isinstance(alerts, list)


def test_detection_privacy_tracker(tmp_path: Path):
    db = Database(tmp_path / "t3.db")
    ls = ListService(db)
    ls._match_tracker_host = lambda _: "tracker.example.com"
    model = ModelEngine(tmp_path / "m2.joblib")
    rule = RuleEngine()
    service = DetectionService(db, ls, model, rule)
    service.start_learning(0)
    feats = [
        {
            "src_ip": "8.8.8.8",
            "dst_ip": "10.0.0.2",
            "src_port": 443,
            "dst_port": 5050,
            "proto": "TCP",
            "packet_rate": 2.0,
            "conn_freq": 1.0,
            "port_visits": 3,
            "session_duration": 5.0,
            "req_interval": 0.2,
            "conn_success_rate": 1.0,
            "avg_pkt_size": 120.0,
            "direction": "inbound",
            "process_id": 100,
            "process_name": "browser.exe",
        }
    ]
    alerts = service.process(feats)
    assert len(alerts) == 1
    assert alerts[0]["sub_category"] == "隐私追踪拦截"
    assert alerts[0]["process_name"] == "browser.exe"


def test_detection_bulk_save_alert_rows(tmp_path: Path):
    db = Database(tmp_path / "t4.db")
    ls = ListService(db)
    model = ModelEngine(tmp_path / "m3.joblib")
    rule = RuleEngine()
    service = DetectionService(db, ls, model, rule)
    rows = [
        (
            "2026-01-01 00:00:00",
            "1.1.1.1",
            "2.2.2.2",
            1234,
            80,
            "TCP",
            "a.exe",
            1,
            "访问与流量类",
            "流量类型异常",
            "high",
            "",
            "",
            "",
            "r",
            0.9,
            "offline",
        ),
        (
            "2026-01-01 00:00:01",
            "3.3.3.3",
            "4.4.4.4",
            2234,
            443,
            "TCP",
            "b.exe",
            2,
            "访问与流量类",
            "流量类型异常",
            "medium",
            "",
            "",
            "",
            "r2",
            0.5,
            "offline",
        ),
    ]
    service._save_alert_rows(rows)
    c = db.conn.cursor()
    c.execute("SELECT COUNT(*) AS cnt FROM alerts")
    assert int(c.fetchone()["cnt"]) == 2


def test_runtime_build_packet_rule_sql():
    sql, args = AppRuntime._build_packet_rule_sql("tcp && port==80 && process contains nginx")
    assert "proto = ?" in sql
    assert "src_port = ?" in sql or "src_port" in sql
    assert "process_name LIKE ?" in sql
    assert "TCP" in args


def test_runtime_build_packet_rule_sql_reject_complex_or_not():
    sql, args = AppRuntime._build_packet_rule_sql("tcp || udp")
    assert sql == ""
    assert args == []


def test_runtime_offline_profile_balanced_mode():
    runtime = AppRuntime()
    profile = runtime.get_offline_import_profile("balanced")
    assert profile.mode == "balanced"
    assert profile.enable_detection is True
    assert profile.store_packets is True
    assert profile.parser_threads >= 1
    assert profile.cpu_limit_percent == 70


def test_runtime_offline_profile_extreme_mode():
    runtime = AppRuntime()
    profile = runtime.get_offline_import_profile("extreme")
    assert profile.mode == "extreme"
    assert profile.enable_detection is False
    assert profile.store_packets is True
    assert profile.raw_hex_preview_bytes == 8
    assert profile.parser_threads >= 1
    assert profile.cpu_limit_percent == 0


def test_runtime_database_routing_summary_shape():
    runtime = AppRuntime()
    summary = runtime.get_database_routing_summary()
    assert "offline_packets" in summary
    assert "alerts" in summary
    assert "core_business" in summary
    assert "id_policy" in summary
    assert summary["alerts"]["engine"] == "sqlite"
    assert summary["core_business"]["engine"] == "sqlite"


def test_detection_ip_bucket_is_stable_and_in_range():
    samples = ["10.0.0.1", "2001:db8::1", "invalid-ip"]
    for ip_text in samples:
        first = DetectionService._ip_to_bucket(ip_text)
        second = DetectionService._ip_to_bucket(ip_text)
        assert first == second
        assert 0 <= first < IP_BUCKETS


def test_detection_vector_uses_deterministic_ip_encoding():
    f = {
        "src_ip": "10.0.0.1",
        "dst_ip": "2001:db8::2",
        "src_port": 1234,
        "dst_port": 443,
        "proto": "TCP",
        "packet_rate": 3.0,
        "conn_freq": 1.0,
        "port_visits": 2,
        "session_duration": 6.0,
        "req_interval": 0.5,
        "conn_success_rate": 0.9,
        "avg_pkt_size": 256.0,
    }
    vector = DetectionService._to_vector(f)
    assert vector[0] == float(int(ipaddress.ip_address("10.0.0.1")) % IP_BUCKETS)
    assert vector[1] == float(int(ipaddress.ip_address("2001:db8::2")) % IP_BUCKETS)


def test_session_aggregator_keeps_process_info():
    aggr = SessionAggregator()
    aggr.ingest_batch(
        [
            {
                "ts": 1.0,
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "src_port": 1234,
                "dst_port": 80,
                "proto": "TCP",
                "length": 100,
                "direction": "outbound",
                "process_id": 321,
                "process_name": "curl.exe",
            }
        ]
    )
    feats = aggr.flush_features(2.0)
    assert len(feats) == 1
    assert feats[0]["process_id"] == 321
    assert feats[0]["process_name"] == "curl.exe"


def test_session_aggregator_uses_precomputed_flags_and_payload():
    aggr = SessionAggregator()
    aggr.ingest_batch(
        [
            {
                "ts": 1.0,
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "src_port": 1234,
                "dst_port": 80,
                "proto": "TCP",
                "length": 100,
                "direction": "outbound",
                "process_id": 321,
                "process_name": "curl.exe",
                "tcp_flags_mask": 0x12,
                "payload_preview": "get /index.php",
            }
        ]
    )
    feats = aggr.flush_features(2.0)
    assert len(feats) == 1
    assert feats[0]["syn_count"] == 1
    assert feats[0]["ack_count"] == 1
    assert feats[0]["payload_preview"] == "get /index.php"


def test_local_dual_account_login(tmp_path: Path):
    db = Database(tmp_path / "auth.db")
    auth = AuthService(db)
    admin = auth.login("admin", "Admin@123456")
    guest = auth.login("user", "User@123456")
    assert admin is not None
    assert guest is not None
    assert admin.role == "admin"
    assert guest.role == "guest"


def test_audit_delete(tmp_path: Path):
    db = Database(tmp_path / "audit.db")
    db.conn.execute(
        "INSERT INTO audit_logs(ts, username, action, target, detail) VALUES(?,?,?,?,?)",
        ("2026-01-01 00:00:00", "admin", "x", "-", "k1"),
    )
    db.conn.execute(
        "INSERT INTO audit_logs(ts, username, action, target, detail) VALUES(?,?,?,?,?)",
        ("2026-01-01 00:00:01", "admin", "x", "-", "k2"),
    )
    db.conn.commit()
    from src.core.audit.service import AuditService

    audit = AuditService(db)
    deleted = audit.delete_logs(keyword="k1")
    assert deleted >= 1


def test_report_generation_with_svg(tmp_path: Path):
    db = Database(tmp_path / "report.db")
    c = db.conn.cursor()
    c.execute(
        "INSERT INTO alerts(ts, src_ip, dst_ip, process_name, process_id, category, sub_category, level, reason, score, handled) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        ("2026-01-01 10:00:00", "10.0.0.8", "10.0.0.1", "browser.exe", 123, "访问与流量类", "流量类型异常", "high", "test", 0.9, 0),
    )
    c.execute(
        "INSERT INTO alerts(ts, src_ip, dst_ip, process_name, process_id, category, sub_category, level, reason, score, handled) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        ("2026-01-01 10:01:00", "10.0.0.9", "10.0.0.1", "updater.exe", 124, "隐私与追踪防护", "隐私追踪拦截", "medium", "tracker", 0.4, 0),
    )
    for i in range(6):
        c.execute(
            "INSERT INTO traffic_stats(ts, inbound_packets, outbound_packets, active_sessions) VALUES(?,?,?,?)",
            (f"2026-01-01 10:0{i}:00", 100 + i * 5, 0, 2 + i),
        )
    db.conn.commit()
    path = tmp_path / "security_report.html"
    service = ReportService(db)
    out = service.generate_visual_report(path)
    text = out.read_text(encoding="utf-8")
    assert out.exists()
    assert "网络安全分析报告" in text
    assert "<svg" in text


def test_notification_high_risk_deduplication(monkeypatch):
    service = NotificationService()
    captured: list[tuple[str, str]] = []

    def fake_send(title: str, message: str) -> bool:
        captured.append((title, message))
        return True

    service._send_notification = fake_send
    high = {"level": "high", "src_ip": "10.0.0.8", "dst_ip": "10.0.0.1", "reason": "risk"}
    ok1 = service.notify_high_risk(high)
    ok2 = service.notify_high_risk(high)
    assert ok1 is True
    assert ok2 is False
    assert len(captured) == 1


def test_capture_engine_subnet_filter_allows_vm_ping_like_packet():
    engine = CaptureEngine(queue.Queue())
    engine.config = CaptureConfig(interface="VMnet8", capture_outbound=False)
    engine.interface_ip = "192.168.197.1"
    engine.interface_ips = {"192.168.197.1"}
    engine.interface_networks = [ipaddress.ip_network("192.168.197.0/24")]
    pkt = type(
        "P",
        (),
        {
            "src_addr": "192.168.197.135",
            "dst_addr": "10.101.234.42",
            "protocol": 1,
            "is_inbound": True,
            "is_outbound": False,
            "src_port": 0,
            "dst_port": 0,
            "raw": b"\x00" * 64,
        },
    )()
    out = engine._normalize(pkt)
    assert out is not None
    assert out["proto"] == "ICMP"


def test_capture_engine_subnet_filter_blocks_unrelated_network_packet():
    engine = CaptureEngine(queue.Queue())
    engine.config = CaptureConfig(interface="VMnet8", capture_outbound=False)
    engine.interface_ip = "192.168.197.1"
    engine.interface_ips = {"192.168.197.1"}
    engine.interface_networks = [ipaddress.ip_network("192.168.197.0/24")]
    pkt = type(
        "P",
        (),
        {
            "src_addr": "10.10.10.2",
            "dst_addr": "10.101.234.42",
            "protocol": 1,
            "is_inbound": True,
            "is_outbound": False,
            "src_port": 0,
            "dst_port": 0,
            "raw": b"\x00" * 64,
        },
    )()
    out = engine._normalize(pkt)
    assert out is None


def test_capture_engine_accepts_pydivert_protocol_tuple():
    engine = CaptureEngine(queue.Queue())
    engine.config = CaptureConfig(interface="VMnet8", capture_outbound=True)
    engine.interface_ip = "192.168.197.1"
    engine.interface_ips = {"192.168.197.1"}
    engine.interface_networks = [ipaddress.ip_network("192.168.197.0/24")]
    pkt = type(
        "P",
        (),
        {
            "src_addr": "192.168.197.135",
            "dst_addr": "10.101.234.42",
            "protocol": (1, 20),
            "is_inbound": True,
            "is_outbound": False,
            "src_port": 0,
            "dst_port": 0,
            "raw": b"\x00" * 64,
        },
    )()
    out = engine._normalize(pkt)
    assert out is not None
    assert out["proto"] == "ICMP"


def test_capture_engine_safe_close_divert_swallow_close_error():
    engine = CaptureEngine(queue.Queue())

    class FakeDivert:
        is_open = True

        def close(self):
            raise OSError(6, "invalid handle")

    engine._safe_close_divert(FakeDivert())


def test_capture_engine_reject_when_not_in_selected_subnet():
    engine = CaptureEngine(queue.Queue())
    engine.config = CaptureConfig(interface="VMnet8", capture_outbound=True)
    engine.interface_networks = [ipaddress.ip_network("172.16.88.0/24")]
    pkt_bad = type(
        "P",
        (),
        {
            "src_addr": "192.168.197.135",
            "dst_addr": "10.101.234.42",
            "protocol": (1, 20),
            "interface": (11, 0),
            "is_inbound": True,
            "is_outbound": False,
            "src_port": 0,
            "dst_port": 0,
            "raw": b"\x00" * 64,
        },
    )()
    assert engine._normalize(pkt_bad) is None


def test_capture_engine_interface_index_mismatch_but_subnet_match_still_accept():
    engine = CaptureEngine(queue.Queue())
    engine.config = CaptureConfig(interface="VMnet8", capture_outbound=True)
    engine.interface_index = 7
    engine.interface_networks = [ipaddress.ip_network("192.168.197.0/24")]
    pkt = type(
        "P",
        (),
        {
            "src_addr": "192.168.197.135",
            "dst_addr": "10.101.234.42",
            "protocol": (1, 20),
            "interface": (11, 0),
            "is_inbound": True,
            "is_outbound": False,
            "src_port": 0,
            "dst_port": 0,
            "raw": b"\x00" * 64,
        },
    )()
    out = engine._normalize(pkt)
    assert out is not None


def test_capture_engine_interface_mismatch_and_no_subnet_match_reject():
    engine = CaptureEngine(queue.Queue())
    engine.config = CaptureConfig(interface="VMnet8", capture_outbound=True)
    engine.interface_index = 7
    engine.interface_networks = []
    engine.interface_ips = {"192.168.197.1"}
    pkt = type(
        "P",
        (),
        {
            "src_addr": "192.168.197.135",
            "dst_addr": "10.101.234.42",
            "protocol": (1, 20),
            "interface": (11, 0),
            "is_inbound": True,
            "is_outbound": False,
            "src_port": 0,
            "dst_port": 0,
            "raw": b"\x00" * 64,
        },
    )()
    out = engine._normalize(pkt)
    assert out is None


def test_capture_engine_network_fallback_to_slash24_when_netmask_missing(monkeypatch):
    class Row:
        def __init__(self, family, address, netmask):
            self.family = family
            self.address = address
            self.netmask = netmask

    monkeypatch.setattr(
        "src.core.capture.capture_engine.psutil.net_if_addrs",
        lambda: {"VMnet8": [Row(socket.AF_INET, "192.168.197.1", None)]},
    )
    nets = CaptureEngine._interface_networks_by_name("VMnet8")
    assert len(nets) >= 1
    assert ipaddress.ip_address("192.168.197.135") in nets[0]


def test_capture_engine_list_interfaces_contains_loopback():
    rows = CaptureEngine.list_interfaces()
    assert any(r["name"] == "__loopback__" for r in rows)


def test_capture_engine_loopback_mode_accepts_loopback_packet():
    engine = CaptureEngine(queue.Queue())
    engine.capture_loopback = True
    engine.config = CaptureConfig(interface="__loopback__", capture_outbound=True)
    pkt = type(
        "P",
        (),
        {
            "src_addr": "127.0.0.1",
            "dst_addr": "127.0.0.1",
            "protocol": (1, 20),
            "is_inbound": True,
            "is_outbound": False,
            "src_port": 0,
            "dst_port": 0,
            "raw": b"\x00" * 64,
        },
    )()
    out = engine._normalize(pkt)
    assert out is not None


def test_capture_engine_loopback_mode_not_blocked_by_outbound_switch():
    engine = CaptureEngine(queue.Queue())
    engine.capture_loopback = True
    engine.interface_ip = "127.0.0.1"
    engine.config = CaptureConfig(interface="__loopback__", capture_outbound=False)
    pkt = type(
        "P",
        (),
        {
            "src_addr": "127.0.0.1",
            "dst_addr": "127.0.0.1",
            "protocol": (1, 20),
            "is_inbound": False,
            "is_outbound": True,
            "src_port": 0,
            "dst_port": 0,
            "raw": b"\x00" * 64,
        },
    )()
    out = engine._normalize(pkt)
    assert out is not None


def test_capture_engine_icmp_not_blocked_by_outbound_switch():
    engine = CaptureEngine(queue.Queue())
    engine.config = CaptureConfig(interface="VMnet8", capture_outbound=False)
    engine.interface_ip = "192.168.197.1"
    engine.interface_ips = {"192.168.197.1"}
    engine.interface_networks = [ipaddress.ip_network("192.168.197.0/24")]
    pkt = type(
        "P",
        (),
        {
            "src_addr": "192.168.197.1",
            "dst_addr": "192.168.197.135",
            "protocol": 1,
            "is_inbound": False,
            "is_outbound": True,
            "src_port": 0,
            "dst_port": 0,
            "raw": b"\x00" * 64,
        },
    )()
    out = engine._normalize(pkt)
    assert out is not None
    assert out["proto"] == "ICMP"
