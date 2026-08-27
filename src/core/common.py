from __future__ import annotations

from datetime import datetime


LEVEL_COLORS: dict[str, str] = {
    "high": "#ef4444",
    "medium": "#f59e0b",
    "low": "#3b82f1",
}
LEVEL_LABELS: dict[str, str] = {
    "high": "高危",
    "medium": "中危",
    "low": "低危",
}
def rank_to_level(rank: int) -> str:
    if int(rank) >= 3:
        return "high"
    if int(rank) == 2:
        return "medium"
    if int(rank) == 1:
        return "low"
    return "normal"


def parse_ts_float(value: object) -> float:
    try:
        return float(value or 0.0)
    except Exception:
        return 0.0


def render_ts_text(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        return datetime.fromtimestamp(float(text)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return text
