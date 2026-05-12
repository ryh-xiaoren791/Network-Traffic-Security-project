from __future__ import annotations

import ipaddress
from collections.abc import Mapping, Sequence

from src.core.packet_inspection import extract_app_fields


CTF_SENSITIVE_PORTS = frozenset({22, 445, 3389, 4444, 1337, 9001})
CTF_SUSPICIOUS_PROCESS_NAMES = frozenset(
    {
        "powershell.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "curl.exe",
        "wget.exe",
        "nc.exe",
        "ncat.exe",
        "python.exe",
    }
)


def _risk_rank(risk_value: str) -> int:
    rv = str(risk_value or "").strip().lower()
    if rv in {"high", "高", "高风险"}:
        return 3
    if rv in {"medium", "中", "中风险"}:
        return 2
    if rv in {"low", "低", "低风险"}:
        return 1
    return 0


def _risk_label_cn(risk_value: str) -> str:
    rv = str(risk_value or "").strip().lower()
    if rv == "high":
        return "高风险"
    if rv == "medium":
        return "中风险"
    if rv == "low":
        return "低风险"
    return "正常"


def _is_private_ip(ip_text: str) -> bool:
    try:
        return ipaddress.ip_address(str(ip_text)).is_private
    except Exception:
        return False


def _remember_clue(clue_map: dict[tuple, dict[str, object]], key: tuple, level_key: str, clue_type: str, summary: str, filter_expr: str, packet_id: int, detail: str) -> None:
    normalized_level = str(level_key or "low").strip().lower()
    candidate: dict[str, object] = {
        "level": _risk_label_cn(normalized_level),
        "level_key": normalized_level,
        "type": clue_type,
        "summary": summary[:180],
        "filter": filter_expr,
        "packet_id": int(packet_id),
        "detail": detail,
    }
    existing = clue_map.get(key)
    if not existing:
        clue_map[key] = candidate
        return
    if _risk_rank(str(candidate.get("level_key", ""))) > _risk_rank(str(existing.get("level_key", ""))):
        clue_map[key] = candidate
        return
    if len(str(candidate.get("summary", ""))) < len(str(existing.get("summary", ""))):
        clue_map[key] = candidate


def build_packet_ctf_clues(
    rows: Sequence[Mapping[str, object]],
    prefetched_details: Mapping[int, Mapping[str, object]] | None = None,
    *,
    max_rows: int = 2000,
    large_payload_bytes: int = 1200,
) -> list[dict[str, object]]:
    clue_map: dict[tuple, dict[str, object]] = {}
    detail_map = prefetched_details or {}
    for row in rows[: max(0, int(max_rows))]:
        packet_id = int(row.get("id", 0) or 0)
        detail = detail_map.get(packet_id, row)
        app, app_fields = extract_app_fields(detail)
        src_ip = str(detail.get("src_ip", "") or "")
        dst_ip = str(detail.get("dst_ip", "") or "")
        process_name = str(detail.get("process_name", "") or "").strip().lower()
        risk = str(detail.get("risk_level", row.get("risk_level", "normal")) or "normal").lower()
        target_name = str(app_fields.get("host") or app_fields.get("query") or app_fields.get("sni") or dst_ip)
        process_hint = process_name or str(row.get("process_name", "") or "-").strip() or "-"
        port_hint = int(detail.get("dst_port", 0) or 0) or int(detail.get("src_port", 0) or 0)
        checks: list[tuple[bool, tuple[tuple, str, str, str, str, str]]] = [
            (
                risk in {"high", "medium"},
                (
                    ("risk", target_name, port_hint, process_hint),
                    risk,
                    "风险流量",
                    f"{_risk_label_cn(risk)}流量: {target_name} | {app} | {process_hint}",
                    "risk==high" if risk == "high" else "risk==medium",
                    f"该流量已被风险关联标记为{_risk_label_cn(risk)}，建议优先查看原始载荷、关联会话与告警上下文。",
                ),
            ),
            (
                _is_private_ip(src_ip) and (not _is_private_ip(dst_ip)),
                (
                    ("outbound", target_name, app, process_hint),
                    "medium",
                    "外联",
                    f"外联: {target_name} | {app} | {process_hint}",
                    f"ip.dst=={dst_ip}",
                    "该连接从本机/内网发往公网，适合排查首次外联、可疑远端或数据外传。",
                ),
            ),
            (
                app in {"HTTP", "DNS", "FTP", "Telnet"},
                (
                    ("cleartext", app, target_name, process_hint),
                    "low",
                    "明文可读",
                    f"明文可读: {app} | {target_name} | {process_hint}",
                    f"proto=={str(row.get('proto', '') or '').upper()}",
                    "该流量更可能含有可直接阅读或提取的应用层内容，适合先查看详情弹窗与会话追踪。",
                ),
            ),
            (
                app == "DNS" and bool(app_fields.get("query")),
                (
                    ("dns", str(app_fields.get("query", "")), str(app_fields.get("query_type", ""))),
                    "medium",
                    "域名请求",
                    f"DNS {app_fields.get('query_type', '')}: {app_fields.get('query', '')}",
                    "port==53",
                    "该线索直接给出 DNS 查询名，适合在 CTF 中快速定位可疑子域名、隧道域名或出题关键词。",
                ),
            ),
            (
                app == "TLS" and bool(app_fields.get("sni")),
                (
                    ("tls-sni", str(app_fields.get("sni", "")), str(app_fields.get("alpn", ""))),
                    "medium",
                    "TLS主机名",
                    f"TLS SNI: {app_fields.get('sni', '')}",
                    "port==443",
                    "该线索提取了 TLS ClientHello 的目标主机名，可在加密流量里快速还原访问目标。",
                ),
            ),
        ]
        if app == "Modbus/TCP" and app_fields.get("function_name"):
            function_name = str(app_fields.get("function_name", "") or "Modbus")
            unit_id = str(app_fields.get("unit_id", "-") or "-")
            target = str(app_fields.get("target", "") or "").strip()
            checks.append(
                (
                    True,
                    (
                        ("modbus", function_name, unit_id, target, process_hint),
                        "medium",
                        "工控Modbus",
                        f"Modbus/TCP {function_name} | unit={unit_id} {target}".strip(),
                        "port==502",
                        "检测到工控 Modbus/TCP 指令，建议重点关注功能码、寄存器地址、数量以及是否出现异常响应。",
                    ),
                )
            )
        if int(detail.get("dst_port", 0) or 0) in CTF_SENSITIVE_PORTS or int(detail.get("src_port", 0) or 0) in CTF_SENSITIVE_PORTS:
            port = int(detail.get("dst_port", 0) or 0) or int(detail.get("src_port", 0) or 0)
            checks.append(
                (
                    True,
                    (
                        ("port", str(port), target_name, process_hint),
                        "medium",
                        "敏感端口",
                        f"敏感端口 {port}: {target_name} | {app}",
                        f"port=={port}",
                        "该流量涉及常见远控、横向或敏感管理端口，CTF/攻防场景下值得优先关注。",
                    ),
                )
            )
        if process_name in CTF_SUSPICIOUS_PROCESS_NAMES:
            checks.append(
                (
                    True,
                    (
                        ("proc", process_name, target_name, app),
                        "medium",
                        "可疑进程",
                        f"{process_name} 发起连接: {target_name} | {app}",
                        f"process=={process_name}",
                        "该连接由脚本/命令行类进程发起，常用于自动化下载、执行命令或题目流量构造。",
                    ),
                )
            )
        if int(detail.get("length", 0) or 0) >= int(large_payload_bytes):
            checks.append(
                (
                    True,
                    (
                        ("payload", target_name, app, process_hint),
                        "low",
                        "大载荷",
                        f"大载荷 {int(detail.get('length', 0) or 0)}B: {target_name} | {app}",
                        f"len>={int(large_payload_bytes)}",
                        "该流量包体较大，适合检查是否包含文件片段、编码数据或一次性提交的敏感内容。",
                    ),
                )
            )
        for enabled, payload in checks:
            if enabled:
                _remember_clue(clue_map, payload[0], payload[1], payload[2], payload[3], payload[4], packet_id, payload[5])
    clues = list(clue_map.values())
    clues.sort(key=lambda item: (-_risk_rank(str(item.get("level_key", ""))), str(item.get("type", "")), str(item.get("summary", ""))))
    return clues[:80]


__all__ = ["build_packet_ctf_clues", "CTF_SENSITIVE_PORTS", "CTF_SUSPICIOUS_PROCESS_NAMES"]
