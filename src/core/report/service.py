from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path

from src.core.storage.db import Database


class ReportService:
    def __init__(self, db: Database) -> None:
        self.db = db

    def generate_visual_report(self, output_path: Path | None = None) -> Path:
        report_path = output_path or Path("reports") / f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        summary = self._query_summary()
        trend_points = self._query_traffic_trend(limit=60)
        level_pairs = self._query_alert_levels()
        top_ip_pairs = self._query_top_abnormal_ips()
        html_text = self._render_html(summary, trend_points, level_pairs, top_ip_pairs)
        report_path.write_text(html_text, encoding="utf-8")
        return report_path

    def _query_summary(self) -> dict:
        c = self.db.conn.cursor()
        c.execute("SELECT COUNT(*) AS cnt FROM alerts")
        total_alerts = int(c.fetchone()["cnt"])
        c.execute("SELECT COUNT(*) AS cnt FROM alerts WHERE level='high'")
        high_alerts = int(c.fetchone()["cnt"])
        c.execute("SELECT COUNT(*) AS cnt FROM alerts WHERE sub_category='隐私追踪拦截'")
        privacy_blocks = int(c.fetchone()["cnt"])
        c.execute("SELECT COUNT(*) AS cnt FROM alerts WHERE ts >= datetime('now', '-24 hours')")
        recent_alerts = int(c.fetchone()["cnt"])
        c.execute("SELECT COUNT(*) AS cnt FROM blacklist_whitelist WHERE list_type='black' AND enabled=1")
        black_items = int(c.fetchone()["cnt"])
        return {
            "total_alerts": total_alerts,
            "high_alerts": high_alerts,
            "privacy_blocks": privacy_blocks,
            "recent_alerts": recent_alerts,
            "black_items": black_items,
        }

    def _query_traffic_trend(self, limit: int = 60) -> list[tuple[str, int]]:
        c = self.db.conn.cursor()
        c.execute(
            "SELECT ts, inbound_packets FROM traffic_stats ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        rows = [dict(r) for r in c.fetchall()]
        rows.reverse()
        points: list[tuple[str, int]] = []
        for row in rows:
            label = str(row["ts"])[11:19] if row["ts"] else ""
            points.append((label, int(row["inbound_packets"] or 0)))
        return points

    def _query_alert_levels(self) -> list[tuple[str, int]]:
        c = self.db.conn.cursor()
        c.execute("SELECT level, COUNT(*) AS cnt FROM alerts GROUP BY level")
        rows = {str(r["level"]): int(r["cnt"]) for r in c.fetchall()}
        return [("high", rows.get("high", 0)), ("medium", rows.get("medium", 0)), ("low", rows.get("low", 0))]

    def _query_top_abnormal_ips(self) -> list[tuple[str, int]]:
        c = self.db.conn.cursor()
        c.execute("SELECT src_ip, COUNT(*) AS cnt FROM alerts GROUP BY src_ip ORDER BY cnt DESC LIMIT 8")
        return [(str(r["src_ip"] or "-"), int(r["cnt"])) for r in c.fetchall()]

    def _render_html(
        self,
        summary: dict,
        trend_points: list[tuple[str, int]],
        level_pairs: list[tuple[str, int]],
        top_ip_pairs: list[tuple[str, int]],
    ) -> str:
        trend_svg = self._line_chart_svg(trend_points, "Inbound Traffic Trend")
        level_svg = self._bar_chart_svg(level_pairs, "Alert Level Distribution")
        top_ip_svg = self._bar_chart_svg(top_ip_pairs, "Top Abnormal Source IPs")
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Security Monitoring Analysis Report</title>
<style>
body{{font-family:Segoe UI,Arial,sans-serif;background:#f4f7fb;color:#1f2937;margin:0;padding:24px;}}
h1{{margin:0 0 8px 0;font-size:28px;}}
.sub{{margin:0 0 24px 0;color:#4b5563;}}
.grid{{display:grid;grid-template-columns:repeat(5,minmax(120px,1fr));gap:12px;margin-bottom:20px;}}
.card{{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:14px;}}
.k{{font-size:12px;color:#6b7280;}}
.v{{font-size:24px;font-weight:700;margin-top:8px;}}
.panel{{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:14px;margin-bottom:16px;}}
svg{{width:100%;height:auto;}}
</style>
</head>
<body>
<h1>Device Security Analysis Report</h1>
<p class="sub">Generated at {html.escape(now)}</p>
<div class="grid">
<div class="card"><div class="k">Total Alerts</div><div class="v">{summary["total_alerts"]}</div></div>
<div class="card"><div class="k">High Risk Alerts</div><div class="v">{summary["high_alerts"]}</div></div>
<div class="card"><div class="k">Privacy Interceptions</div><div class="v">{summary["privacy_blocks"]}</div></div>
<div class="card"><div class="k">Alerts in 24h</div><div class="v">{summary["recent_alerts"]}</div></div>
<div class="card"><div class="k">Enabled Blacklist</div><div class="v">{summary["black_items"]}</div></div>
</div>
<div class="panel">{trend_svg}</div>
<div class="panel">{level_svg}</div>
<div class="panel">{top_ip_svg}</div>
</body>
</html>
""".strip()

    def _line_chart_svg(self, points: list[tuple[str, int]], title: str) -> str:
        width = 900
        height = 320
        pad_left = 52
        pad_bottom = 48
        plot_w = width - pad_left - 24
        plot_h = height - 44 - pad_bottom
        values = [v for _, v in points] or [0]
        max_v = max(values) if max(values) > 0 else 1
        if len(points) <= 1:
            points = points or [("N/A", 0)]
            points = points + [("N/A", points[0][1])]
        coords = []
        for i, (_, v) in enumerate(points):
            x = pad_left + int(i * plot_w / max(1, len(points) - 1))
            y = 24 + int((1 - (v / max_v)) * plot_h)
            coords.append((x, y))
        poly = " ".join(f"{x},{y}" for x, y in coords)
        axis_color = "#9ca3af"
        line_color = "#2563eb"
        labels = []
        for i in range(0, len(points), max(1, len(points) // 6)):
            lx = pad_left + int(i * plot_w / max(1, len(points) - 1))
            labels.append(
                f"<text x='{lx}' y='{height-18}' text-anchor='middle' font-size='11' fill='#6b7280'>{html.escape(points[i][0])}</text>"
            )
        y_marks = []
        for step in range(0, 5):
            val = int(max_v * (4 - step) / 4)
            y = 24 + int(step * plot_h / 4)
            y_marks.append(f"<line x1='{pad_left}' y1='{y}' x2='{width-24}' y2='{y}' stroke='#e5e7eb' />")
            y_marks.append(
                f"<text x='{pad_left-8}' y='{y+4}' text-anchor='end' font-size='11' fill='#6b7280'>{val}</text>"
            )
        return (
            f"<svg viewBox='0 0 {width} {height}' xmlns='http://www.w3.org/2000/svg'>"
            f"<text x='14' y='18' font-size='16' font-weight='700' fill='#111827'>{html.escape(title)}</text>"
            f"{''.join(y_marks)}"
            f"<line x1='{pad_left}' y1='{height-pad_bottom}' x2='{width-24}' y2='{height-pad_bottom}' stroke='{axis_color}'/>"
            f"<line x1='{pad_left}' y1='24' x2='{pad_left}' y2='{height-pad_bottom}' stroke='{axis_color}'/>"
            f"<polyline points='{poly}' fill='none' stroke='{line_color}' stroke-width='2.5'/>"
            f"{''.join(labels)}"
            f"</svg>"
        )

    def _bar_chart_svg(self, pairs: list[tuple[str, int]], title: str) -> str:
        width = 900
        height = 320
        left = 64
        top = 36
        bottom = 52
        right = 24
        values = [v for _, v in pairs] or [0]
        max_v = max(values) if max(values) > 0 else 1
        bar_area_w = width - left - right
        bar_area_h = height - top - bottom
        bar_w = max(24, int(bar_area_w / max(1, len(pairs) * 2)))
        gap = bar_w
        x = left + 10
        bars = []
        labels = []
        for label, value in pairs:
            h = int((value / max_v) * (bar_area_h - 6))
            y = top + bar_area_h - h
            bars.append(f"<rect x='{x}' y='{y}' width='{bar_w}' height='{h}' fill='#10b981' rx='4' />")
            bars.append(
                f"<text x='{x + bar_w / 2}' y='{y - 6}' text-anchor='middle' font-size='11' fill='#374151'>{value}</text>"
            )
            labels.append(
                f"<text x='{x + bar_w / 2}' y='{height-20}' text-anchor='middle' font-size='11' fill='#6b7280'>{html.escape(label)}</text>"
            )
            x += bar_w + gap
        return (
            f"<svg viewBox='0 0 {width} {height}' xmlns='http://www.w3.org/2000/svg'>"
            f"<text x='14' y='22' font-size='16' font-weight='700' fill='#111827'>{html.escape(title)}</text>"
            f"<line x1='{left}' y1='{height-bottom}' x2='{width-right}' y2='{height-bottom}' stroke='#9ca3af'/>"
            f"{''.join(bars)}"
            f"{''.join(labels)}"
            f"</svg>"
        )
