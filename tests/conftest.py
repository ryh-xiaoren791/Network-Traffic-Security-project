from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from src.config import AppConfig
from src.core.storage.db import Database, hash_password


@pytest.fixture
def tmp_db_path(tmp_path: Path) -> Path:
    return tmp_path / "test.db"


@pytest.fixture
def tmp_db(tmp_db_path: Path) -> Database:
    db = Database(tmp_db_path)
    yield db
    try:
        db.conn.close()
    except Exception:
        pass


@pytest.fixture
def app_config(tmp_path: Path) -> AppConfig:
    return AppConfig(
        db_path=tmp_path / "system.db",
        model_path=tmp_path / "iforest_model.joblib",
        offline_duckdb_path=tmp_path / "offline_packets.duckdb",
        offline_use_duckdb=False,
    )


@pytest.fixture
def sample_packet_dict():
    return {
        "id": 1,
        "src_ip": "192.168.1.100",
        "dst_ip": "93.184.216.34",
        "src_port": 54321,
        "dst_port": 80,
        "proto": "TCP",
        "src_mac": "aa:bb:cc:dd:ee:ff",
        "dst_mac": "11:22:33:44:55:66",
        "length": 1500,
        "flags": 24,
        "raw_hex": "45000034",
        "raw_ascii": "GET / HTTP/1.0",
        "app_protocol": "HTTP",
        "timestamp": "2026-01-01 12:00:00",
        "process_name": "chrome.exe",
        "process_pid": 1234,
        "direction": "outbound",
        "interface_name": "eth0",
        "source": "live",
    }


@pytest.fixture
def sample_packets_batch():
    return [
        {
            "id": i,
            "src_ip": f"192.168.1.{100 + i}",
            "dst_ip": "93.184.216.34",
            "src_port": 50000 + i,
            "dst_port": 80,
            "proto": "TCP",
            "src_mac": f"aa:bb:cc:dd:ee:{i:02x}",
            "dst_mac": "11:22:33:44:55:66",
            "length": 200 + i * 10,
            "flags": 24,
            "raw_hex": f"450000{(34 + i):04x}",
            "raw_ascii": f"GET /page{i} HTTP/1.0",
            "app_protocol": "HTTP",
            "timestamp": f"2026-01-01 12:00:{i:02d}",
            "process_name": "chrome.exe",
            "process_pid": 1000,
            "direction": "outbound",
            "interface_name": "eth0",
            "source": "live",
        }
        for i in range(5)
    ]


@pytest.fixture
def detection_features_batch():
    return [
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
        },
        {
            "src_ip": "10.0.0.3",
            "dst_ip": "10.0.0.4",
            "src_port": 5678,
            "dst_port": 443,
            "proto": "TCP",
            "packet_rate": 10.0,
            "conn_freq": 5.0,
            "port_visits": 20,
            "session_duration": 30.0,
            "req_interval": 0.5,
            "conn_success_rate": 0.9,
            "avg_pkt_size": 500.0,
            "direction": "outbound",
        },
    ]


@pytest.fixture
def mock_runtime():
    rt = Mock()
    rt.offline_progress = {"percent": 0, "alerts": 0, "packets": 0, "running": False}
    return rt


@pytest.fixture
def mock_detector():
    det = Mock()
    det.learning_until = 0.0
    det.in_learning.return_value = False
    return det


@pytest.fixture
def offline_profile_speed():
    return SimpleNamespace(
        enable_detection=False,
        mode="speed",
        parser_threads=2,
        cpu_limit_percent=0,
        batch_size=128,
        raw_hex_preview_bytes=4,
        enable_app_meta=False,
        store_packets=False,
    )


@pytest.fixture
def offline_profile_detect():
    return SimpleNamespace(
        enable_detection=True,
        mode="detect",
        parser_threads=4,
        cpu_limit_percent=60,
        batch_size=256,
        raw_hex_preview_bytes=8,
        enable_app_meta=True,
        store_packets=False,
    )
