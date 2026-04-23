from __future__ import annotations

from pathlib import Path
import argparse
import json
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import psutil

from src.app.runtime import AppRuntime
from src.core.offline.adapter import OfflineParserConfig, iter_offline_batches


def _run_with_metrics(runner) -> tuple[dict, float, float]:
    proc = psutil.Process()
    stop_flag = {"stop": False}
    peak_rss_mb = {"value": 0.0}
    cpu_peak = {"value": 0.0}
    proc.cpu_percent(interval=None)

    def sampler() -> None:
        while not stop_flag["stop"]:
            try:
                rss_mb = proc.memory_info().rss / (1024 * 1024)
                cpu = proc.cpu_percent(interval=0.05)
                peak_rss_mb["value"] = max(peak_rss_mb["value"], rss_mb)
                cpu_peak["value"] = max(cpu_peak["value"], cpu)
            except Exception:
                time.sleep(0.05)

    th = threading.Thread(target=sampler, daemon=True)
    th.start()
    try:
        result = runner()
    finally:
        stop_flag["stop"] = True
        th.join(timeout=0.5)
    return result, round(peak_rss_mb["value"], 2), round(cpu_peak["value"], 2)


def benchmark_parse_only(pcap_path: Path, batch_size: int, raw_hex_preview_bytes: int, enable_app_meta: bool) -> dict:
    cfg = OfflineParserConfig(
        batch_size=batch_size,
        raw_hex_preview_bytes=max(0, int(raw_hex_preview_bytes)),
        prefer_native=True,
        fallback_to_scapy=False,
        enable_app_meta=bool(enable_app_meta),
    )
    def run() -> dict:
        begin = time.perf_counter()
        packets = 0
        for batch in iter_offline_batches(pcap_path, cfg):
            packets += len(batch.packets)
        sec = max(1e-9, time.perf_counter() - begin)
        return {
            "mode": "parse_only_native",
            "packets": packets,
            "seconds": round(sec, 6),
            "pps": round(packets / sec, 2),
        }

    result, peak_rss_mb, cpu_peak = _run_with_metrics(run)
    result["peak_rss_mb"] = peak_rss_mb
    result["cpu_peak_percent"] = cpu_peak
    return result


def benchmark_full_pipeline(pcap_path: Path, mode: str) -> dict:
    def run() -> dict:
        runtime = AppRuntime()
        begin = time.perf_counter()
        packets, alerts = runtime.import_offline_pcap(pcap_path, mode=mode)
        sec = max(1e-9, time.perf_counter() - begin)
        return {
            "mode": f"full_pipeline_{mode}",
            "packets": packets,
            "alerts": alerts,
            "seconds": round(sec, 6),
            "pps": round(packets / sec, 2),
        }

    result, peak_rss_mb, cpu_peak = _run_with_metrics(run)
    result["peak_rss_mb"] = peak_rss_mb
    result["cpu_peak_percent"] = cpu_peak
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Offline CTF benchmark")
    parser.add_argument("--pcap", required=True, help="pcap/pcapng path")
    parser.add_argument("--batch-size", type=int, default=5000, help="native batch size")
    parser.add_argument("--mode", choices=["balanced", "extreme"], default="balanced", help="offline import mode")
    args = parser.parse_args()
    p = Path(args.pcap)
    if not p.exists():
        raise FileNotFoundError(f"pcap not found: {p}")
    runtime = AppRuntime()
    profile = runtime.get_offline_import_profile(args.mode)
    result = {
        "file": str(p),
        "bytes": p.stat().st_size,
        "profile": {
            "mode": profile.mode,
            "batch_size": profile.batch_size,
            "parser_threads": profile.parser_threads,
            "cpu_limit_percent": profile.cpu_limit_percent,
            "raw_hex_preview_bytes": profile.raw_hex_preview_bytes,
            "store_packets": profile.store_packets,
            "store_raw_hex": profile.store_raw_hex,
            "enable_app_meta": profile.enable_app_meta,
            "enable_detection": profile.enable_detection,
        },
        "parse": benchmark_parse_only(
            p,
            max(1000, int(args.batch_size)),
            profile.raw_hex_preview_bytes,
            profile.enable_app_meta,
        ),
        "pipeline": benchmark_full_pipeline(p, profile.mode),
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
