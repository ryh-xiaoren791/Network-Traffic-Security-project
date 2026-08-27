import json

from scripts.benchmark_guard import _mean_ci95, compare_benchmark_groups


def test_mean_ci95_single_sample_has_zero_width_interval() -> None:
    avg, lower, upper = _mean_ci95([12.5])
    assert avg == 12.5
    assert lower == 12.5
    assert upper == 12.5


def test_compare_benchmark_groups_accepts_healthy_current_run(tmp_path) -> None:
    baseline = {
        "parse": {"seconds": 10.0, "pps": 1000.0, "peak_rss_mb": 100.0, "cpu_peak_percent": 40.0},
        "pipeline": {"seconds": 20.0, "pps": 500.0, "peak_rss_mb": 200.0, "cpu_peak_percent": 60.0},
    }
    current = {
        "parse": {"seconds": 9.8, "pps": 1010.0, "peak_rss_mb": 99.0, "cpu_peak_percent": 39.0},
        "pipeline": {"seconds": 19.7, "pps": 510.0, "peak_rss_mb": 198.0, "cpu_peak_percent": 58.0},
    }
    baseline_path = tmp_path / "baseline.json"
    current_path = tmp_path / "current.json"
    baseline_path.write_text(json.dumps(baseline), encoding="utf-8")
    current_path.write_text(json.dumps(current), encoding="utf-8")
    report = compare_benchmark_groups([baseline_path], [current_path])
    assert report["ok"] is True
    assert all(metric["healthy"] for metric in report["metrics"])
