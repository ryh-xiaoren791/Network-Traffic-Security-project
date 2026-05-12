from __future__ import annotations

import os
from pathlib import Path

from src.core.offline import OfflineParserConfig, OfflineParserError, iter_offline_batches


def import_offline_pcap(runtime, pcap_path: Path, mode: str = "") -> tuple[int, int]:
    total_file_bytes = int(os.path.getsize(pcap_path)) if pcap_path.exists() else 0
    profile = runtime.get_offline_import_profile(mode)
    runtime._offline_cpu_last_sample = 0.0
    runtime.clear_offline_analysis_data(clear_alerts=bool(profile.enable_detection))
    runtime._begin_offline_write_mode(profile)
    start_alert_id = runtime._current_alert_max_id()
    learning_until_backup = float(getattr(runtime.detector, "learning_until", 0.0))
    if runtime.detector.in_learning():
        runtime.detector.learning_until = 0.0
    runtime.offline_progress = {
        "running": True,
        "processed": 0,
        "alerts": 0,
        "generic_frames": 0,
        "file": str(pcap_path),
        "percent": 0.0,
        "bytes": 0,
        "total_bytes": total_file_bytes,
        "mode": profile.mode,
        "parser_threads": profile.parser_threads,
        "cpu_limit_percent": profile.cpu_limit_percent,
    }
    total_packets = 0
    total_alerts = 0
    try:
        parser_cfg = OfflineParserConfig(
            batch_size=profile.batch_size,
            raw_hex_preview_bytes=profile.raw_hex_preview_bytes,
            prefer_native=True,
            fallback_to_scapy=True,
            enable_app_meta=profile.enable_app_meta,
            worker_threads=profile.parser_threads,
        )
        if profile.store_packets and runtime._offline_store_enabled():
            runtime.offline_progress["generic_frames"] = runtime._import_offline_generic_frames(pcap_path, parser_cfg, profile)
        for packet_batch in iter_offline_batches(pcap_path, parser_cfg):
            batch = packet_batch.packets
            alerts = runtime._process_offline_batch(batch, profile)
            runtime._apply_offline_cpu_limit(profile)
            total_packets += len(batch)
            total_alerts += alerts
            runtime.offline_progress["processed"] = total_packets
            runtime.offline_progress["alerts"] = total_alerts
            current_bytes = int(packet_batch.bytes_read or 0)
            runtime.offline_progress["bytes"] = current_bytes
            if total_file_bytes > 0:
                runtime.offline_progress["percent"] = min(100.0, (current_bytes / total_file_bytes) * 100.0)
        total_alerts += runtime._flush_remaining_offline_features()
        total_alerts += runtime._flush_offline_feature_buffer(force=True)
        runtime.offline_progress["bytes"] = total_file_bytes
        runtime.offline_progress["percent"] = 100.0
        final_alerts = max(total_alerts, runtime._count_new_alerts(start_alert_id, source="offline"))
        runtime.offline_progress["alerts"] = final_alerts
        return total_packets, final_alerts
    except OfflineParserError as exc:
        raise RuntimeError(str(exc)) from exc
    finally:
        runtime._end_offline_write_mode()
        runtime.detector.learning_until = learning_until_backup
        runtime.offline_progress["running"] = False


__all__ = ["import_offline_pcap"]
