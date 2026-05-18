from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from src.core.common import LEVEL_COLORS, LEVEL_LABELS, render_ts_text
from src.core.storage.db import Database

if TYPE_CHECKING:
    from src.core.storage.offline_packet_store import OfflinePacketStore

_PROTO_COLORS: dict[str, str] = {
    "TCP": "#6366f1", "UDP": "#10b981", "ICMP": "#f59e0b", "HTTP": "#ef4444",
    "DNS": "#8b5cf6", "TLS": "#ec4899", "SSH": "#14b8a6", "Modbus/TCP": "#f97316",
    "OTHER": "#94a3b8",
}

_OFFLINE_SIZE_BUCKETS = [
    (0, 100, "0-100"),
    (101, 500, "100-500"),
    (501, 1000, "500-1000"),
    (1001, 1500, "1000-1500"),
    (1501, 3000, "1500-3000"),
    (3001, 999999, "3000+"),
]

_SENSITIVE_PORTS = {22, 3389, 445, 4444, 1337, 9001}
_SENSITIVE_PORT_LABELS: dict[int, str] = {
    22: "SSH", 3389: "RDP", 445: "SMB", 4444: "Metasploit", 1337: "1337", 9001: "9001",
}


class ReportService:
    def __init__(self, db: Database, offline_packet_store: OfflinePacketStore | None = None) -> None:
        self.db = db
        self.offline_packet_store = offline_packet_store

    def generate_visual_report(self, source: str | Path = "live", output_path: Path | None = None) -> Path:
        if isinstance(source, Path):
            output_path = source
            report_source = "live"
        else:
            report_source = "offline" if str(source or "").strip().lower() == "offline" else "live"
        suffix = "traffic" if report_source == "offline" else "realtime"
        report_path = output_path or Path("reports") / f"security_report_{suffix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        report_path.parent.mkdir(parents=True, exist_ok=True)

        if report_source == "offline":
            html_text = self._render_offline(report_path)
        else:
            html_text = self._render_realtime(report_source)
        report_path.write_text(html_text, encoding="utf-8")
        return report_path

    # ==================================================================
    # DuckDB / SQLite 离线查询辅助
    # ==================================================================

    def _offline_sql(self, sql: str) -> str:
        if self.offline_packet_store is not None:
            return sql
        return sql.replace("offline_packets", "captured_packets")

    def _offline_execute(self, sql: str, params: list | tuple | None = None):
        query_sql = self._offline_sql(sql)
        query_params = list(params or [])
        if self.offline_packet_store is not None:
            return self.offline_packet_store.conn.execute(query_sql, query_params)
        return self.db.conn.execute(query_sql, query_params)

    def _offline_fetch(self, sql: str, params: list | None = None) -> list:
        return self._offline_execute(sql, params).fetchall()

    def _offline_fetch_one(self, sql: str, params: list | None = None) -> tuple | None:
        return self._offline_execute(sql, params).fetchone()

    def _offline_count(self, condition_sql: str = "", params: list | tuple | None = None) -> int:
        row = self._offline_fetch_one(
            "SELECT COUNT(*) FROM offline_packets WHERE source='offline'" + condition_sql,  # nosec
            params,
        )
        return int(row[0]) if row else 0

    # ==================================================================
    # 实时监测报告
    # ==================================================================

    def _render_realtime(self, source: str) -> str:
        summary = self._query_summary(source)
        trend_points = self._query_traffic_trend_sqlite(source, limit=60)
        level_pairs = self._query_alert_levels(source)
        top_ip_pairs = self._query_top_abnormal_ips(source)
        attack_type_pairs = self._query_attack_types(source)
        recent_alerts = self._query_recent_alerts(source, limit=15)
        recommendations = self._query_recommendations(source)

        report_title = "网络安全分析报告 - 实时监测"
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        posture = self._live_posture(summary)
        cards_html = self._render_live_cards(summary)
        trend_svg = self._line_chart_svg(trend_points, "流量趋势（数据包 / 分钟）")
        level_svg = self._bar_chart_svg(level_pairs, "告警等级分布", color_map=LEVEL_COLORS)
        attack_svg = self._bar_chart_svg(attack_type_pairs, "攻击类型分布")
        top_ip_svg = self._bar_chart_svg(top_ip_pairs, "异常来源 IP Top 8")
        table_html = self._render_alert_table(recent_alerts)
        recs_html = self._render_recommendations(recommendations)

        return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>{html.escape(report_title)}</title>
<style>{self._css()}</style>
</head>
<body>

<header class="report-header live-header">
  <h1>{html.escape(report_title)}</h1>
  <div class="header-meta">
    <span class="meta-item">生成时间：{html.escape(now)}</span>
    <span class="source-badge live-badge">实时监测</span>
  </div>
</header>

<main class="report-body">

  <section class="posture-section">
    <h2 class="section-title">安全态势综述</h2>
    <p class="posture-text">{posture}</p>
  </section>

  <section>
    <h2 class="section-title">关键指标</h2>
    {cards_html}
  </section>

  <section>
    <h2 class="section-title">流量趋势</h2>
    <div class="chart-panel">{trend_svg}</div>
  </section>

  <section class="chart-row">
    <div class="chart-col">
      <h2 class="section-title">告警等级分布</h2>
      <div class="chart-panel">{level_svg}</div>
    </div>
    <div class="chart-col">
      <h2 class="section-title">攻击类型分布</h2>
      <div class="chart-panel">{attack_svg}</div>
    </div>
  </section>

  <section>
    <h2 class="section-title">异常来源 IP Top 8</h2>
    <div class="chart-panel">{top_ip_svg}</div>
  </section>

  <section>
    <h2 class="section-title">最新告警明细</h2>
    {table_html}
  </section>

  <section>
    <h2 class="section-title">安全建议与处置方案</h2>
    {recs_html}
  </section>

</main>

<footer class="report-footer">
  <p>本报告由 AI Traffic Guard 实时监测模块自动生成，仅供内部安全分析参考</p>
</footer>

</body>
</html>"""

    # ==================================================================
    # 离线流量分析报告
    # ==================================================================

    def _render_offline(self, report_path: Path) -> str:
        stats = self._query_offline_stats()
        stats["alert_count"] = self._query_offline_alert_count()
        proto_pairs = self._query_offline_proto_dist()
        ip_pair_pairs = self._query_offline_top_ip_pairs(limit=8)
        port_pairs = self._query_offline_top_ports(limit=8)
        size_pairs = self._query_offline_size_dist()
        alert_clues = self._query_offline_alerts()
        observations = self._build_ctf_observations()

        report_title = "流量分析报告 - 离线流量分析"
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        overview_html = self._render_offline_overview(stats)
        cards_html = self._render_offline_cards(stats)
        proto_svg = self._bar_chart_svg(proto_pairs, "协议分布", color_map=_PROTO_COLORS)
        ip_pair_svg = self._bar_chart_svg(ip_pair_pairs, "Top IP 通信对")
        port_svg = self._bar_chart_svg(port_pairs, "目的端口分布")
        size_svg = self._bar_chart_svg(size_pairs, "数据包大小分布")
        clues_html = self._render_ctf_section(alert_clues, observations)

        return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>{html.escape(report_title)}</title>
<style>{self._css()}</style>
</head>
<body>

<header class="report-header offline-header">
  <h1>{html.escape(report_title)}</h1>
  <div class="header-meta">
    <span class="meta-item">生成时间：{html.escape(now)}</span>
    <span class="source-badge offline-badge">离线流量分析</span>
  </div>
</header>

<main class="report-body">

  <section>
    <h2 class="section-title">流量概览综述</h2>
    {overview_html}
  </section>

  <section>
    <h2 class="section-title">关键指标卡片</h2>
    {cards_html}
  </section>

  <section>
    <h2 class="section-title">协议分布</h2>
    <div class="chart-panel">{proto_svg}</div>
  </section>

  <section class="chart-row">
    <div class="chart-col">
      <h2 class="section-title">Top IP 通信对</h2>
      <div class="chart-panel">{ip_pair_svg}</div>
    </div>
    <div class="chart-col">
      <h2 class="section-title">目的端口分布</h2>
      <div class="chart-panel">{port_svg}</div>
    </div>
  </section>

  <section>
    <h2 class="section-title">数据包大小分布</h2>
    <div class="chart-panel">{size_svg}</div>
  </section>

  {clues_html}

</main>

<footer class="report-footer">
  <p>本报告由 AI Traffic Guard 离线分析模块自动生成，仅供内部安全分析参考</p>
</footer>

</body>
</html>"""

    # ==================================================================
    # 实时监测 - SQLite 查询
    # ==================================================================

    def _query_summary(self, source: str) -> dict:
        c = self.db.conn.cursor()
        c.execute(
            """
            SELECT
                COALESCE(SUM(CASE WHEN source=? THEN 1 ELSE 0 END), 0) AS total_alerts,
                COALESCE(SUM(CASE WHEN source=? AND level='high' THEN 1 ELSE 0 END), 0) AS high_alerts,
                COALESCE(SUM(CASE WHEN source=? AND level='medium' THEN 1 ELSE 0 END), 0) AS medium_alerts,
                COALESCE(SUM(CASE WHEN source=? AND level='low' THEN 1 ELSE 0 END), 0) AS low_alerts,
                COALESCE(SUM(CASE WHEN source=? AND sub_category='隐私追踪拦截' THEN 1 ELSE 0 END), 0) AS privacy_blocks,
                COALESCE(SUM(CASE WHEN source=? AND ts >= datetime('now', '-24 hours') THEN 1 ELSE 0 END), 0) AS recent_alerts,
                COALESCE(SUM(CASE WHEN source=? AND handled=0 THEN 1 ELSE 0 END), 0) AS unhandled_alerts
            FROM alerts
            """,
            (source, source, source, source, source, source, source),
        )
        alert_summary = dict(c.fetchone() or {})
        c.execute("SELECT COUNT(*) AS cnt FROM blacklist_whitelist WHERE list_type='black' AND enabled=1")
        black_items = int((c.fetchone() or {"cnt": 0})["cnt"])
        return {
            "total_alerts": int(alert_summary.get("total_alerts") or 0),
            "high_alerts": int(alert_summary.get("high_alerts") or 0),
            "medium_alerts": int(alert_summary.get("medium_alerts") or 0),
            "low_alerts": int(alert_summary.get("low_alerts") or 0),
            "privacy_blocks": int(alert_summary.get("privacy_blocks") or 0),
            "recent_alerts": int(alert_summary.get("recent_alerts") or 0),
            "unhandled_alerts": int(alert_summary.get("unhandled_alerts") or 0),
            "black_items": black_items,
        }

    def _query_traffic_trend_sqlite(self, source: str, limit: int = 60) -> list[tuple[str, int]]:
        c = self.db.conn.cursor()
        c.execute(
            "SELECT substr(ts, 1, 16) AS ts_minute, COUNT(*) AS packet_count "
            "FROM captured_packets WHERE source=? GROUP BY ts_minute ORDER BY ts_minute DESC LIMIT ?",
            (source, limit),
        )
        rows = [dict(r) for r in c.fetchall()]
        rows.reverse()
        points: list[tuple[str, int]] = []
        for row in rows:
            ts_text = str(row.get("ts_minute") or "")
            label = ts_text[11:16] if len(ts_text) >= 16 else ts_text
            points.append((label, int(row.get("packet_count") or 0)))
        return points

    def _query_alert_levels(self, source: str) -> list[tuple[str, int]]:
        c = self.db.conn.cursor()
        c.execute("SELECT level, COUNT(*) AS cnt FROM alerts WHERE source=? GROUP BY level", (source,))
        rows = {str(r["level"]): int(r["cnt"]) for r in c.fetchall()}
        return [("高危", rows.get("high", 0)), ("中危", rows.get("medium", 0)), ("低危", rows.get("low", 0))]

    def _query_top_abnormal_ips(self, source: str) -> list[tuple[str, int]]:
        c = self.db.conn.cursor()
        c.execute(
            "SELECT src_ip, COUNT(*) AS cnt FROM alerts WHERE source=? GROUP BY src_ip ORDER BY cnt DESC LIMIT 8",
            (source,),
        )
        return [(str(r["src_ip"] or "-"), int(r["cnt"])) for r in c.fetchall()]

    def _query_attack_types(self, source: str) -> list[tuple[str, int]]:
        c = self.db.conn.cursor()
        c.execute(
            "SELECT COALESCE(NULLIF(category,''), NULLIF(attack_type,''), '未分类') AS cat, COUNT(*) AS cnt "
            "FROM alerts WHERE source=? GROUP BY cat ORDER BY cnt DESC LIMIT 8",
            (source,),
        )
        return [(str(r["cat"]), int(r["cnt"])) for r in c.fetchall()]

    def _query_recent_alerts(self, source: str, limit: int = 15) -> list[dict]:
        c = self.db.conn.cursor()
        c.execute(
            "SELECT ts, level, category, sub_category, attack_type, attack_desc, "
            "src_ip, dst_ip, src_port, dst_port, proto "
            "FROM alerts WHERE source=? ORDER BY ts DESC LIMIT ?",
            (source, limit),
        )
        return [dict(r) for r in c.fetchall()]

    def _query_recommendations(self, source: str) -> list[dict]:
        c = self.db.conn.cursor()
        c.execute(
            "SELECT DISTINCT attack_type, attack_desc, mitigation FROM alerts "
            "WHERE source=? AND level='high' AND mitigation IS NOT NULL AND mitigation != '' "
            "ORDER BY ts DESC LIMIT 6",
            (source,),
        )
        return [dict(r) for r in c.fetchall()]

    # ==================================================================
    # 离线分析 - 数据查询
    # ==================================================================

    def _query_offline_stats(self) -> dict:
        row = self._offline_fetch_one(
            "SELECT COUNT(*) AS total, COALESCE(SUM(length), 0) AS total_bytes, "
            "MIN(ts) AS time_start, MAX(ts) AS time_end, "
            "COALESCE(MAX(length), 0) AS max_packet, "
            "CAST(COALESCE(AVG(length), 0) AS INTEGER) AS avg_packet, "
            "COUNT(DISTINCT proto) AS proto_count "
            "FROM offline_packets WHERE source='offline'"
        )
        if row is None:
            return {
                "total": 0, "total_bytes": 0, "time_start": "", "time_end": "",
                "max_packet": 0, "avg_packet": 0, "proto_count": 0,
                "unique_ips": 0, "session_pairs": 0,
            }

        unique_ips_row = self._offline_fetch_one(
            "SELECT COUNT(DISTINCT ip) AS cnt FROM ("
            "SELECT src_ip AS ip FROM offline_packets WHERE source='offline' "
            "UNION SELECT dst_ip AS ip FROM offline_packets WHERE source='offline'"
            ")"
        )
        unique_ips = int(unique_ips_row[0]) if unique_ips_row else 0

        pairs_row = self._offline_fetch_one(
            "SELECT COUNT(*) AS cnt FROM ("
            "SELECT DISTINCT src_ip, dst_ip FROM offline_packets WHERE source='offline'"
            ")"
        )
        session_pairs = int(pairs_row[0]) if pairs_row else 0

        return {
            "total": int(row[0] or 0),
            "total_bytes": int(row[1] or 0),
            "time_start": render_ts_text(row[2]),
            "time_end": render_ts_text(row[3]),
            "max_packet": int(row[4] or 0),
            "avg_packet": int(row[5] or 0),
            "proto_count": int(row[6] or 0),
            "unique_ips": unique_ips,
            "session_pairs": session_pairs,
        }

    def _query_offline_proto_dist(self) -> list[tuple[str, int]]:
        rows = self._offline_fetch(
            "SELECT proto, COUNT(*) AS cnt FROM offline_packets "
            "WHERE source='offline' GROUP BY proto ORDER BY cnt DESC LIMIT 8"
        )
        return [(str(r[0] or "OTHER"), int(r[1])) for r in rows]

    def _query_offline_top_ip_pairs(self, limit: int = 8) -> list[tuple[str, int]]:
        rows = self._offline_fetch(
            "SELECT src_ip, dst_ip, COUNT(*) AS cnt FROM offline_packets "
            "WHERE source='offline' GROUP BY src_ip, dst_ip ORDER BY cnt DESC LIMIT ?",
            (limit,),
        )
        return [(f"{r[0]}→{r[1]}", int(r[2])) for r in rows]

    def _query_offline_top_ports(self, limit: int = 8) -> list[tuple[str, int]]:
        rows = self._offline_fetch(
            "SELECT dst_port, COUNT(*) AS cnt FROM offline_packets "
            "WHERE source='offline' GROUP BY dst_port ORDER BY cnt DESC LIMIT ?",
            (limit,),
        )
        return [(str(r[0]), int(r[1])) for r in rows]

    def _query_offline_size_dist(self) -> list[tuple[str, int]]:
        cases_parts: list[str] = []
        for lo, hi, label in _OFFLINE_SIZE_BUCKETS:
            cases_parts.append(f"WHEN length BETWEEN {lo} AND {hi} THEN '{label}'")
        cases_sql = " ".join(cases_parts)
        rows = self._offline_fetch(
            f"SELECT CASE {cases_sql} ELSE '3000+' END AS bucket, COUNT(*) AS cnt "
            "FROM offline_packets WHERE source='offline' GROUP BY bucket ORDER BY 1"  # nosec
        )
        result = [(str(r[0]), int(r[1])) for r in rows]
        bucket_order = {label: i for i, (_, _, label) in enumerate(_OFFLINE_SIZE_BUCKETS)}
        result.sort(key=lambda x: bucket_order.get(x[0], 99))
        return result

    def _query_offline_alerts(self) -> list[dict]:
        c = self.db.conn.cursor()
        c.execute(
            "SELECT ts, level, attack_type, attack_desc, mitigation, src_ip, dst_ip "
            "FROM alerts WHERE source='offline' ORDER BY ts DESC LIMIT 12"
        )
        return [dict(r) for r in c.fetchall()]

    def _query_offline_alert_count(self) -> int:
        c = self.db.conn.cursor()
        c.execute("SELECT COUNT(*) FROM alerts WHERE source='offline'")
        row = c.fetchone()
        return int(row[0]) if row else 0

    # ==================================================================
    # CTF 取证线索自动观察
    # ==================================================================

    def _build_ctf_observations(self) -> list[dict]:
        observations: list[dict] = []

        # 敏感端口检查
        sens_cases_parts = []
        for p in sorted(_SENSITIVE_PORTS):
            label = _SENSITIVE_PORT_LABELS.get(p, str(p))
            sens_cases_parts.append(f"WHEN dst_port={p} THEN '{label}({p})' WHEN src_port={p} THEN '{label}({p})'")
        if sens_cases_parts:
            sens_cases = " ".join(sens_cases_parts)
            sens_rows = self._offline_fetch(
                f"SELECT CASE {sens_cases} END AS port_label, COUNT(*) AS cnt "  # nosec
                "FROM offline_packets WHERE source='offline' AND ("
                + " OR ".join(f"dst_port={p} OR src_port={p}" for p in sorted(_SENSITIVE_PORTS))
                + ") GROUP BY port_label ORDER BY cnt DESC"
            )
            for sens_row in sens_rows:
                port_label = str(sens_row[0] or "")
                cnt = int(sens_row[1])
                if port_label and cnt > 0:
                    observations.append({
                        "type": "敏感端口通信",
                        "level": "medium",
                        "detail": f"检测到 {cnt} 个数据包使用敏感端口 {port_label}，建议排查是否为后门或横向移动行为",
                    })

        # TLS/443
        tls_cnt = self._offline_count(" AND (dst_port=443 OR src_port=443)")
        if tls_cnt > 0:
            observations.append({
                "type": "加密流量",
                "level": "low",
                "detail": f"检测到 {tls_cnt} 个 TLS/443 端口通信包，建议检查 SNI 域名和 TLS 证书信息以识别通信目标",
            })

        # DNS
        dns_cnt = self._offline_count(" AND (dst_port=53 OR src_port=53)")
        if dns_cnt > 0:
            observations.append({
                "type": "DNS 查询",
                "level": "low",
                "detail": f"检测到 {dns_cnt} 个 DNS 查询包，建议检查是否有异常域名请求、DNS 隧道或 DGA 特征",
            })

        # HTTP
        http_cnt = self._offline_count(" AND (dst_port=80 OR src_port=80)")
        if http_cnt > 0:
            observations.append({
                "type": "明文 HTTP",
                "level": "low",
                "detail": f"检测到 {http_cnt} 个 HTTP 明文通信包，建议检查请求内容是否包含敏感信息泄露",
            })

        # Modbus
        modbus_cnt = self._offline_count(" AND (dst_port=502 OR src_port=502)")
        if modbus_cnt > 0:
            observations.append({
                "type": "工业协议 Modbus",
                "level": "medium",
                "detail": f"检测到 {modbus_cnt} 个 Modbus/TCP (端口502) 通信包，建议检查功能码和寄存器操作",
            })

        # ICMP
        icmp_cnt = self._offline_count(" AND proto='ICMP'")
        if icmp_cnt > 0:
            observations.append({
                "type": "ICMP 流量",
                "level": "low",
                "detail": f"检测到 {icmp_cnt} 个 ICMP 数据包，可能用于网络扫描、隧道通信或隐蔽信道",
            })

        # 大载荷数据包
        large_cnt = self._offline_count(" AND length > 3000")
        if large_cnt > 0:
            observations.append({
                "type": "大载荷数据包",
                "level": "medium",
                "detail": f"检测到 {large_cnt} 个大于 3000 字节的大载荷数据包，建议检查是否包含文件传输或数据泄露行为",
            })

        return observations

    # ==================================================================
    # 实时监测 - 子区块渲染
    # ==================================================================

    def _live_posture(self, summary: dict) -> str:
        total = summary["total_alerts"]
        high = summary["high_alerts"]
        medium = summary["medium_alerts"]
        unhandled = summary["unhandled_alerts"]
        if total == 0:
            return "当前网络安全态势良好，未检测到异常活动。建议继续保持现有安全策略和监控配置。"
        parts = []
        if high > 0:
            parts.append(f"检测到 <strong>{high}</strong> 个高危告警，安全态势<strong>严峻</strong>，建议立即排查异常来源并检查是否存在未授权访问或数据泄露风险")
        elif medium > 0:
            parts.append(f"中危告警 <strong>{medium}</strong> 个占比较高，网络环境中存在可疑活动，建议重点关注异常通信模式")
        else:
            parts.append("当前仅存在少量低危告警，整体安全态势可控")
        if unhandled > 0:
            parts.append(f"仍有 <strong>{unhandled}</strong> 个告警未处理，建议尽快完成排查与处置，避免潜在风险扩大")
        return "。".join(parts) + "。"

    def _render_live_cards(self, summary: dict) -> str:
        items = [
            ("告警总数", summary["total_alerts"], ""),
            ("高危告警", summary["high_alerts"], "high"),
            ("中危告警", summary["medium_alerts"], "medium"),
            ("低危告警", summary["low_alerts"], "low"),
            ("24h 新增", summary["recent_alerts"], ""),
            ("未处理告警", summary["unhandled_alerts"], "high" if summary["unhandled_alerts"] > 0 else ""),
            ("隐私追踪拦截", summary["privacy_blocks"], ""),
            ("启用黑名单", summary["black_items"], ""),
        ]
        rows: list[str] = []
        for label, value, color_key in items:
            accent = LEVEL_COLORS.get(color_key, "#6366f1")
            rows.append(
                f'<div class="metric-card" style="border-left:4px solid {accent}">'
                f'<div class="metric-label">{html.escape(label)}</div>'
                f'<div class="metric-value" style="color:{accent}">{value}</div>'
                f"</div>"
            )
        return '<div class="metric-grid">' + "".join(rows) + "</div>"

    def _render_alert_table(self, alerts: list[dict]) -> str:
        if not alerts:
            return '<div class="empty-state">暂无告警记录</div>'
        rows: list[str] = []
        for a in alerts:
            level = str(a.get("level") or "low")
            level_cn = LEVEL_LABELS.get(level, level)
            level_color = LEVEL_COLORS.get(level, "#6b7280")
            ts = str(a.get("ts") or "-")
            if len(ts) >= 16:
                ts = ts[5:16]
            attack = str(a.get("attack_type") or a.get("category") or a.get("sub_category") or "-")
            desc = str(a.get("attack_desc") or "-")
            ip_info = f'{a.get("src_ip") or "-"} → {a.get("dst_ip") or "-"}'
            rows.append(
                "<tr>"
                f"<td>{html.escape(ts)}</td>"
                f'<td><span class="level-badge" style="background:{level_color}">{html.escape(level_cn)}</span></td>'
                f"<td>{html.escape(attack)}</td>"
                f'<td class="ip-cell">{html.escape(ip_info)}</td>'
                f'<td class="desc-cell">{html.escape(desc)}</td>'
                "</tr>"
            )
        return (
            '<div class="table-wrap"><table class="alert-table">'
            "<thead><tr>"
            "<th>时间</th><th>等级</th><th>攻击类型</th><th>来源 IP → 目标 IP</th><th>描述</th>"
            "</tr></thead>"
            f"<tbody>{''.join(rows)}</tbody>"
            "</table></div>"
        )

    def _render_recommendations(self, recs: list[dict]) -> str:
        if not recs:
            return "<p>暂无高危告警处置建议。当前网络环境处于可控状态，继续保持日常监测即可。</p>"
        seen: set[str] = set()
        items: list[str] = []
        for r in recs:
            mitigation = str(r.get("mitigation") or "").strip()
            if not mitigation or mitigation in seen:
                continue
            seen.add(mitigation)
            attack_type = str(r.get("attack_type") or "")
            attack_desc = str(r.get("attack_desc") or "")
            title = attack_type or attack_desc or "高危告警"
            items.append(
                '<div class="rec-item">'
                f'<div class="rec-title">{html.escape(title)}</div>'
                f'<div class="rec-body">{html.escape(mitigation)}</div>'
                "</div>"
            )
        if not items:
            return "<p>暂无高危告警处置建议。当前网络环境处于可控状态，继续保持日常监测即可。</p>"
        return "".join(items)

    # ==================================================================
    # 离线分析 - 子区块渲染
    # ==================================================================

    def _render_offline_overview(self, stats: dict) -> str:
        total = stats["total"]
        if total == 0:
            return '<div class="empty-state">当前无离线流量数据。请先导入 PCAP 文件进行流量分析。</div>'
        mb = stats["total_bytes"] / (1024 * 1024)
        duration = ""
        if stats["time_start"] and stats["time_end"]:
            try:
                a = datetime.strptime(stats["time_start"], "%Y-%m-%d %H:%M:%S")
                b = datetime.strptime(stats["time_end"], "%Y-%m-%d %H:%M:%S")
                delta = b - a
                mins = int(delta.total_seconds() // 60)
                secs = int(delta.total_seconds() % 60)
                duration = f"{mins}分{secs}秒" if mins > 0 else f"{secs}秒"
            except ValueError:
                duration = ""
        parts = [
            f"本次分析共捕获 <strong>{total:,}</strong> 个数据包，",
            f"总流量 <strong>{mb:.2f} MB</strong>，",
            f"覆盖 <strong>{stats['unique_ips']}</strong> 个独立 IP 地址，",
        ]
        if stats["time_start"]:
            parts.append(
                f"时间跨度从 <strong>{stats['time_start']}</strong> 至 <strong>{stats['time_end']}</strong>"
                + (f"（{duration}）" if duration else "")
                + "。"
            )
        else:
            parts[-1] = parts[-1].rstrip("，") + "。"
        return "<p>" + "".join(parts) + "</p>"

    def _render_offline_cards(self, stats: dict) -> str:
        total_bytes = stats.get("total_bytes", 0)
        mb = total_bytes / (1024 * 1024)
        items = [
            ("总数据包数", f"{stats['total']:,}", "#6366f1"),
            ("总流量", f"{mb:.1f} MB", "#10b981"),
            ("独立 IP 数", str(stats["unique_ips"]), "#f59e0b"),
            ("通信会话对数", str(stats["session_pairs"]), "#ec4899"),
            ("协议种类数", str(stats["proto_count"]), "#8b5cf6"),
            ("告警检出数", str(stats.get("alert_count", 0)), "#ef4444"),
            ("最大包", f"{stats['max_packet']} B", "#14b8a6"),
            ("平均包大小", f"{stats['avg_packet']} B", "#f97316"),
        ]
        rows: list[str] = []
        for label, value, color in items:
            rows.append(
                f'<div class="metric-card" style="border-left:4px solid {color}">'
                f'<div class="metric-label">{html.escape(label)}</div>'
                f'<div class="metric-value" style="color:{color}">{value}</div>'
                f"</div>"
            )
        return '<div class="metric-grid">' + "".join(rows) + "</div>"

    def _render_ctf_section(self, alerts: list[dict], observations: list[dict]) -> str:
        if not alerts and not observations:
            return ""

        parts: list[str] = []
        parts.append('<section>')
        parts.append('<h2 class="section-title">异常流量线索 / CTF 取证要点</h2>')
        parts.append('<div class="clue-grid">')

        for obs in observations:
            level = obs.get("level", "low")
            level_color = LEVEL_COLORS.get(level, "#6b7280")
            obs_type = html.escape(obs.get("type", ""))
            obs_detail = html.escape(obs.get("detail", ""))
            parts.append(
                f'<div class="ctf-card" style="border-left:4px solid {level_color}">'
                f'<div class="ctf-type" style="color:{level_color}">📌 {obs_type}</div>'
                f'<div class="ctf-detail">{obs_detail}</div>'
                f"</div>"
            )

        for a in alerts:
            level = str(a.get("level") or "low")
            level_color = LEVEL_COLORS.get(level, "#6b7280")
            attack_type = html.escape(str(a.get("attack_type") or "未分类"))
            attack_desc = html.escape(str(a.get("attack_desc") or ""))
            mitigation = html.escape(str(a.get("mitigation") or ""))
            parts.append(
                f'<div class="ctf-card alert-clue" style="border-left:4px solid {level_color}">'
                f'<div class="ctf-type" style="color:{level_color}">⚠️ {attack_type}</div>'
                f'<div class="ctf-detail">{attack_desc}</div>'
                + (f'<div class="ctf-mitigation">建议：{mitigation}</div>' if mitigation else "")
                + "</div>"
            )

        parts.append("</div>")
        parts.append("</section>")
        return "\n".join(parts)

    # ==================================================================
    # SVG 图表
    # ==================================================================

    def _bar_chart_svg(
        self,
        pairs: list[tuple[str, int]],
        title: str = "",
        color_map: dict[str, str] | None = None,
    ) -> str:
        if not pairs:
            return (
                '<svg viewBox="0 0 600 200" xmlns="http://www.w3.org/2000/svg">'
                '<text x="300" y="105" text-anchor="middle" fill="#94a3b8" font-size="14">暂无数据</text>'
                "</svg>"
            )
        w, h = 600, 240
        ml, mr, mt, mb = 60, 20, 30, 55
        pw = w - ml - mr
        ph = h - mt - mb
        n = len(pairs)
        gap = pw / n
        bar_w = max(10, min(50, gap * 0.75))
        max_v = max(v for _, v in pairs) or 1

        parts: list[str] = []
        for i, (label, val) in enumerate(pairs):
            x = ml + i * gap
            bar_h = max(2, int(val / max_v * ph))
            y = mt + ph - bar_h
            color = (color_map or {}).get(label, "#6366f1")
            rx = x + (gap - bar_w) / 2
            parts.append(
                f'<rect x="{rx:.1f}" y="{y:.1f}" width="{bar_w:.1f}" height="{bar_h:.1f}" '
                f'fill="{color}" rx="3" />'
            )
            lbl = html.escape(str(label)[:12])
            parts.append(
                f'<text x="{x + gap / 2:.1f}" y="{mt + ph + 14}" text-anchor="end" '
                f'font-size="9" fill="#475569" transform="rotate(-35,{x + gap / 2:.1f},{mt + ph + 14})">{lbl}</text>'
            )
            parts.append(
                f'<text x="{x + gap / 2:.1f}" y="{y - 6:.1f}" text-anchor="middle" '
                f'font-size="10" fill="#1e293b" font-weight="600">{val}</text>'
            )

        title_el = ""
        if title:
            title_el = f'<text x="{w / 2}" y="18" text-anchor="middle" font-size="13" fill="#64748b">{html.escape(title)}</text>'
        return (f'<svg viewBox="0 0 {w} {h}" xmlns="http://www.w3.org/2000/svg">'
                f'{title_el}'
                f'<line x1="{ml}" y1="{mt+ph}" x2="{w-mr}" y2="{mt+ph}" stroke="#cbd5e1" stroke-width="1"/>'
                f'{"".join(parts)}'
                f'</svg>')

    def _line_chart_svg(
        self,
        points: list[tuple[str, int]],
        title: str = "",
    ) -> str:
        if len(points) < 2:
            return (
                '<svg viewBox="0 0 600 200" xmlns="http://www.w3.org/2000/svg">'
                '<text x="300" y="105" text-anchor="middle" fill="#94a3b8" font-size="14">暂无数据</text>'
                '</svg>'
            )
        w, h = 600, 240
        ml, mr, mt, mb = 52, 20, 22, 48
        pw = w - ml - mr
        ph = h - mt - mb
        values = [v for _, v in points]
        max_v = max(values) if max(values) > 0 else 1

        coords: list[str] = []
        for i, (_, v) in enumerate(points):
            x = ml + int(i * pw / max(1, len(points) - 1))
            y = mt + int((1 - (v / max_v)) * ph)
            coords.append(f"{x},{y}")
        poly = " ".join(coords)
        area = f"{poly} {coords[-1].split(',')[0]},{mt+ph} {coords[0].split(',')[0]},{mt+ph}"

        grid_lines: list[str] = []
        for step in range(0, 5):
            y = mt + int(step * ph / 4)
            grid_lines.append(f'<line x1="{ml}" y1="{y}" x2="{w-mr}" y2="{y}" stroke="#e2e8f0" stroke-width="1"/>')

        y_marks: list[str] = []
        for step in range(0, 5):
            val = int(max_v * (4 - step) / 4)
            y = mt + int(step * ph / 4)
            y_marks.append(f'<text x="{ml-8}" y="{y+4}" text-anchor="end" font-size="9" fill="#64748b">{val}</text>')

        x_labels: list[str] = []
        step = max(1, len(points) // 6)
        for i in range(0, len(points), step):
            lx = ml + int(i * pw / max(1, len(points) - 1))
            x_labels.append(
                f'<text x="{lx}" y="{mt+ph+20}" text-anchor="middle" font-size="9" fill="#94a3b8">'
                f'{html.escape(points[i][0])}</text>'
            )

        title_el = ""
        if title:
            title_el = f'<text x="{w/2}" y="16" text-anchor="middle" font-size="13" fill="#64748b">{html.escape(title)}</text>'
        return (
            f'<svg viewBox="0 0 {w} {h}" xmlns="http://www.w3.org/2000/svg">'
            '<defs>'
            '<linearGradient id="areaGrad2" x1="0" y1="0" x2="0" y2="1">'
            '<stop offset="0%" stop-color="#6366f1" stop-opacity="0.25"/>'
            '<stop offset="100%" stop-color="#6366f1" stop-opacity="0.02"/>'
            '</linearGradient>'
            '</defs>'
            f'{title_el}'
            f'{"".join(grid_lines)}'
            f'{"".join(y_marks)}'
            f'<line x1="{ml}" y1="{mt+ph}" x2="{w-mr}" y2="{mt+ph}" stroke="#cbd5e1" stroke-width="1.5"/>'
            f'<line x1="{ml}" y1="{mt}" x2="{ml}" y2="{mt+ph}" stroke="#cbd5e1" stroke-width="1.5"/>'
            f'<polygon points="{area}" fill="url(#areaGrad2)"/>'
            f'<polyline points="{poly}" fill="none" stroke="#6366f1" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>'
            f'{"".join(x_labels)}'
            f'</svg>'
        )

    def _css(self) -> str:
        return """
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:"Microsoft YaHei","PingFang SC",Segoe UI,Arial,sans-serif;background:#f1f5f9;color:#1e293b;line-height:1.6;}

.report-header{padding:36px 40px 28px;color:#fff;}
.report-header h1{font-size:26px;font-weight:700;letter-spacing:.5px;}
.live-header{background:linear-gradient(135deg,#0f172a 0%,#1e293b 100%);}
.offline-header{background:linear-gradient(135deg,#1e3a5f 0%,#0f172a 100%);}
.header-meta{margin-top:12px;display:flex;align-items:center;gap:16px;font-size:13px;color:#94a3b8;}
.source-badge{display:inline-block;padding:3px 12px;border-radius:20px;font-size:12px;font-weight:600;}
.live-badge{background:rgba(239,68,68,.3);color:#fecaca;}
.offline-badge{background:rgba(16,185,129,.3);color:#a7f3d0;}

.report-body{max-width:1160px;margin:0 auto;padding:28px 24px 40px;}

.section-title{font-size:17px;font-weight:700;color:#0f172a;margin-bottom:14px;padding-left:12px;border-left:4px solid #6366f1;}

.posture-section,.clue-section,.overview-section{background:#fff;border-radius:12px;padding:20px 24px;margin-bottom:24px;box-shadow:0 1px 3px rgba(0,0,0,.06);}
.posture-text,.overview-text{font-size:14px;color:#334155;line-height:1.8;}

.metric-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:24px;}
.metric-card{background:#fff;border-radius:10px;padding:16px 18px;box-shadow:0 1px 3px rgba(0,0,0,.05);}
.metric-label{font-size:12px;color:#64748b;margin-bottom:6px;}
.metric-value{font-size:28px;font-weight:800;}

.chart-panel{background:#fff;border-radius:12px;padding:18px;box-shadow:0 1px 3px rgba(0,0,0,.05);}
.chart-panel svg{width:100%;height:auto;display:block;}

.chart-row{display:flex;gap:18px;margin-bottom:0;}
.chart-col{flex:1;min-width:0;}

.table-wrap{background:#fff;border-radius:12px;padding:4px;box-shadow:0 1px 3px rgba(0,0,0,.05);overflow-x:auto;margin-bottom:24px;}
.alert-table{width:100%;border-collapse:collapse;font-size:13px;}
.alert-table thead th{background:#f8fafc;text-align:left;padding:10px 12px;font-weight:700;color:#475569;border-bottom:2px solid #e2e8f0;white-space:nowrap;}
.alert-table tbody td{padding:9px 12px;border-bottom:1px solid #f1f5f9;color:#334155;}
.alert-table tbody tr:hover{background:#f8fafc;}
.alert-table tbody tr:nth-child(even){background:#fafbfc;}
.alert-table tbody tr:nth-child(even):hover{background:#f1f5f9;}
.ip-cell{font-family:"Cascadia Code","Fira Code",Consolas,monospace;font-size:12px;}
.desc-cell{max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}

.level-badge{display:inline-block;padding:2px 10px;border-radius:12px;color:#fff;font-size:11px;font-weight:600;}

.rec-item{background:#fff;border-radius:10px;padding:14px 18px;margin-bottom:10px;box-shadow:0 1px 3px rgba(0,0,0,.05);border-left:4px solid #ef4444;}
.rec-title{font-size:14px;font-weight:700;color:#1e293b;margin-bottom:4px;}
.rec-body{font-size:13px;color:#475569;line-height:1.7;}

.clue-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:12px;}
.ctf-card{background:#fff;border-radius:10px;padding:14px 16px;box-shadow:0 1px 3px rgba(0,0,0,.05);}
.ctf-card.alert-clue{background:#fef2f2;}
.ctf-type{font-size:13px;font-weight:700;margin-bottom:6px;}
.ctf-detail{font-size:12px;color:#475569;line-height:1.6;}
.ctf-mitigation{font-size:12px;color:#059669;margin-top:6px;padding-top:6px;border-top:1px solid #d1fae5;}

.empty-state{background:#fff;border-radius:12px;padding:40px;text-align:center;color:#94a3b8;font-size:14px;}

.report-footer{text-align:center;padding:20px;color:#94a3b8;font-size:12px;border-top:1px solid #e2e8f0;margin-top:20px;}
"""
