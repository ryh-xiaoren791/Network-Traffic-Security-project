from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from statistics import mean, stdev


MetricSpec = tuple[str, str]
DEFAULT_METRICS: tuple[MetricSpec, ...] = (
    ("parse.seconds", "lower"),
    ("parse.pps", "higher"),
    ("parse.peak_rss_mb", "lower"),
    ("parse.cpu_peak_percent", "lower"),
    ("pipeline.seconds", "lower"),
    ("pipeline.pps", "higher"),
    ("pipeline.peak_rss_mb", "lower"),
    ("pipeline.cpu_peak_percent", "lower"),
)


def _load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _pick_metric(payload: dict, metric_path: str) -> float:
    current: object = payload
    for part in metric_path.split("."):
        if not isinstance(current, dict) or part not in current:
            raise KeyError(f"missing metric: {metric_path}")
        current = current[part]
    return float(current)


def _mean_ci95(values: list[float]) -> tuple[float, float, float]:
    if not values:
        raise ValueError("values must not be empty")
    avg = mean(values)
    if len(values) == 1:
        return avg, avg, avg
    margin = 1.96 * (stdev(values) / math.sqrt(len(values)))
    return avg, avg - margin, avg + margin


def _guard_threshold(direction: str, baseline_lower: float, baseline_upper: float, tolerance: float) -> float:
    if direction == "higher":
        return baseline_lower * tolerance
    if tolerance <= 0:
        raise ValueError("tolerance must be > 0")
    return baseline_upper / tolerance


def _is_metric_healthy(direction: str, current_mean: float, baseline_lower: float, baseline_upper: float, tolerance: float) -> bool:
    threshold = _guard_threshold(direction, baseline_lower, baseline_upper, tolerance)
    if direction == "higher":
        return current_mean >= threshold
    return current_mean <= threshold


def compare_benchmark_groups(
    baseline_files: list[Path],
    current_files: list[Path],
    metrics: tuple[MetricSpec, ...] = DEFAULT_METRICS,
    tolerance: float = 0.95,
) -> dict:
    baseline_payloads = [_load_json(path) for path in baseline_files]
    current_payloads = [_load_json(path) for path in current_files]
    report_metrics: list[dict] = []
    overall_ok = True
    for metric_path, direction in metrics:
        baseline_values = [_pick_metric(payload, metric_path) for payload in baseline_payloads]
        current_values = [_pick_metric(payload, metric_path) for payload in current_payloads]
        baseline_mean, baseline_lower, baseline_upper = _mean_ci95(baseline_values)
        current_mean, current_lower, current_upper = _mean_ci95(current_values)
        healthy = _is_metric_healthy(direction, current_mean, baseline_lower, baseline_upper, tolerance)
        overall_ok = overall_ok and healthy
        report_metrics.append(
            {
                "metric": metric_path,
                "direction": direction,
                "baseline": {
                    "mean": round(baseline_mean, 6),
                    "ci95_lower": round(baseline_lower, 6),
                    "ci95_upper": round(baseline_upper, 6),
                    "samples": len(baseline_values),
                },
                "current": {
                    "mean": round(current_mean, 6),
                    "ci95_lower": round(current_lower, 6),
                    "ci95_upper": round(current_upper, 6),
                    "samples": len(current_values),
                },
                "threshold": round(_guard_threshold(direction, baseline_lower, baseline_upper, tolerance), 6),
                "healthy": healthy,
            }
        )
    return {"ok": overall_ok, "tolerance": tolerance, "metrics": report_metrics}


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compare benchmark outputs with a 95% CI guardrail.")
    parser.add_argument("--baseline", nargs="+", required=True, help="baseline benchmark json files")
    parser.add_argument("--current", nargs="+", required=True, help="current benchmark json files")
    parser.add_argument("--tolerance", type=float, default=0.95, help="guardrail tolerance, default 0.95")
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    report = compare_benchmark_groups(
        baseline_files=[Path(path) for path in args.baseline],
        current_files=[Path(path) for path in args.current],
        tolerance=float(args.tolerance),
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if not report["ok"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
