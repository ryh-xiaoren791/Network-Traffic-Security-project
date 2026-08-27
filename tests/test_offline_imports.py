from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from src.app.offline_imports import import_offline_pcap
from src.core.offline import OfflineParserError


def test_import_offline_pcap_updates_progress_and_restores_detector(tmp_path) -> None:
    pcap_path = tmp_path / "demo.pcap"
    pcap_path.write_bytes(b"x" * 100)
    profile = SimpleNamespace(
        enable_detection=True,
        mode="detect",
        parser_threads=4,
        cpu_limit_percent=60,
        batch_size=256,
        raw_hex_preview_bytes=8,
        enable_app_meta=True,
        store_packets=False,
    )
    detector = Mock()
    detector.learning_until = 42.0
    detector.in_learning.return_value = True
    runtime = Mock()
    runtime.detector = detector
    runtime.get_offline_import_profile.return_value = profile
    runtime._process_offline_batch.side_effect = [1, 2]
    runtime._flush_remaining_offline_features.return_value = 3
    runtime._flush_offline_feature_buffer.return_value = 4
    runtime._count_new_alerts.return_value = 12
    runtime._offline_store_enabled.return_value = False
    runtime.offline_progress = {}

    batches = [
        SimpleNamespace(packets=[{"id": 1}], bytes_read=40),
        SimpleNamespace(packets=[{"id": 2}, {"id": 3}], bytes_read=90),
    ]
    with patch("src.app.offline_imports.iter_offline_batches", return_value=iter(batches)):
        packets, alerts = import_offline_pcap(runtime, pcap_path, mode="detect")

    assert (packets, alerts) == (3, 12)
    runtime.clear_offline_analysis_data.assert_called_once_with(clear_alerts=True)
    runtime._begin_offline_write_mode.assert_called_once_with(profile)
    assert runtime._apply_offline_cpu_limit.call_count == 2
    runtime._end_offline_write_mode.assert_called_once()
    assert runtime.offline_progress["percent"] == 100.0
    assert runtime.offline_progress["alerts"] == 12
    assert runtime.offline_progress["running"] is False
    assert detector.learning_until == 42.0


def test_import_offline_pcap_wraps_parser_error_and_finishes_cleanup(tmp_path) -> None:
    pcap_path = tmp_path / "bad.pcap"
    pcap_path.write_bytes(b"bad")
    profile = SimpleNamespace(
        enable_detection=False,
        mode="speed",
        parser_threads=2,
        cpu_limit_percent=0,
        batch_size=128,
        raw_hex_preview_bytes=4,
        enable_app_meta=False,
        store_packets=False,
    )
    detector = Mock()
    detector.learning_until = 7.0
    detector.in_learning.return_value = False
    runtime = Mock()
    runtime.detector = detector
    runtime.get_offline_import_profile.return_value = profile
    runtime._offline_store_enabled.return_value = False
    runtime.offline_progress = {}

    with patch("src.app.offline_imports.iter_offline_batches", side_effect=OfflineParserError("boom")):
        with pytest.raises(RuntimeError, match="boom"):
            import_offline_pcap(runtime, pcap_path, mode="speed")

    runtime._end_offline_write_mode.assert_called_once()
    assert runtime.offline_progress["running"] is False
    assert detector.learning_until == 7.0
