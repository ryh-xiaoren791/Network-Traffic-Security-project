from __future__ import annotations

import re
from collections.abc import Mapping


def parse_packet_rule_term(term: str) -> tuple[str, str, str] | None:
    match = re.match(r"^([a-zA-Z0-9_.]+)\s*(==|!=|>=|<=|>|<)\s*(.+)$", term.strip())
    if not match:
        return None
    field = str(match.group(1) or "").strip().lower()
    op = str(match.group(2) or "").strip()
    value = str(match.group(3) or "").strip().strip("'").strip('"')
    return field, op, value


def _lookup_contains_text(row: Mapping[str, object], field: str) -> str:
    if field in {"process", "process_name"}:
        return str(row.get("process_name", ""))
    if field in {"ip", "ip.addr"}:
        return f"{row.get('src_ip', '')} {row.get('dst_ip', '')}"
    if field in {"proto", "source", "risk"}:
        key = "risk_level" if field == "risk" else field
        return str(row.get(key, ""))
    return str(row.get(field, ""))


def _flatten_packet_row(row: Mapping[str, object], include_risk_text: bool) -> str:
    fields = [
        str(row.get("src_ip", "")),
        str(row.get("dst_ip", "")),
        str(row.get("proto", "")),
        str(row.get("process_name", "")),
        str(row.get("source", "")),
    ]
    if include_risk_text:
        fields.append(str(row.get("risk_level", "")))
    return " ".join(fields).lower()


def _extract_compare_values(row: Mapping[str, object], field: str) -> list[object]:
    if field in {"ip.src", "src_ip"}:
        return [str(row.get("src_ip", ""))]
    if field in {"ip.dst", "dst_ip"}:
        return [str(row.get("dst_ip", ""))]
    if field in {"ip.addr", "ip"}:
        return [str(row.get("src_ip", "")), str(row.get("dst_ip", ""))]
    if field in {"port", "tcp.port", "udp.port"}:
        return [int(row.get("src_port", 0) or 0), int(row.get("dst_port", 0) or 0)]
    if field in {"tcp.srcport", "udp.srcport", "src_port"}:
        return [int(row.get("src_port", 0) or 0)]
    if field in {"tcp.dstport", "udp.dstport", "dst_port"}:
        return [int(row.get("dst_port", 0) or 0)]
    if field in {"frame.len", "len", "length"}:
        return [int(row.get("length", 0) or 0)]
    if field in {"frame.number", "no", "id"}:
        return [int(row.get("id", 0) or 0)]
    if field in {"frame.time_delta", "delta"}:
        return [float(row.get("ts_epoch", 0.0) or 0.0)]
    if field in {"risk", "risk_level"}:
        return [str(row.get("risk_level", ""))]
    if field in {"process", "process_name"}:
        return [str(row.get("process_name", ""))]
    if field in {"proto", "source", "ts", "time"}:
        key = "ts" if field in {"ts", "time"} else field
        return [row.get(key, "")]
    return [row.get(field, "")]


def _compare_rule_value(value: object, op: str, expected_raw: str, expected_num: float | None) -> bool:
    if expected_num is not None:
        try:
            actual_num = float(value)
        except Exception:
            return False
        if op == "==":
            return actual_num == expected_num
        if op == "!=":
            return actual_num != expected_num
        if op == ">":
            return actual_num > expected_num
        if op == "<":
            return actual_num < expected_num
        if op == ">=":
            return actual_num >= expected_num
        if op == "<=":
            return actual_num <= expected_num
        return False
    actual = str(value).lower()
    expected = expected_raw.lower()
    if op == "==":
        return actual == expected
    if op == "!=":
        return actual != expected
    if op == ">":
        return actual > expected
    if op == "<":
        return actual < expected
    if op == ">=":
        return actual >= expected
    if op == "<=":
        return actual <= expected
    return False


def match_packet_term(row: Mapping[str, object], term: str, include_risk_text: bool = True) -> bool:
    normalized = term.strip().lower()
    if not normalized:
        return True
    if normalized in {"tcp", "udp", "icmp"}:
        return str(row.get("proto", "")).lower() == normalized
    contains_match = re.match(r"^([a-zA-Z0-9_.]+)\s+contains\s+(.+)$", normalized)
    if contains_match:
        field = str(contains_match.group(1) or "").strip()
        value = str(contains_match.group(2) or "").strip().strip("'").strip('"')
        return value.lower() in _lookup_contains_text(row, field).lower()
    parsed = parse_packet_rule_term(normalized)
    if not parsed:
        return normalized in _flatten_packet_row(row, include_risk_text)
    field, op, expected_raw = parsed
    try:
        expected_num = float(expected_raw)
    except Exception:
        expected_num = None
    values = _extract_compare_values(row, field)
    def comparator(value):
        return _compare_rule_value(value, op, expected_raw, expected_num)
    if op == "!=":
        return all(comparator(value) for value in values)
    return any(comparator(value) for value in values)


def match_packet_rule(row: Mapping[str, object], expression: str, include_risk_text: bool = True) -> bool:
    expr = str(expression or "").strip()
    if not expr:
        return True
    or_parts = [part.strip() for part in expr.split("||") if part.strip()]
    if not or_parts:
        return True
    for or_part in or_parts:
        and_parts = [part.strip() for part in or_part.split("&&") if part.strip()]
        matched = True
        for raw_term in and_parts:
            term = raw_term
            negate = False
            while term.startswith("!"):
                negate = not negate
                term = term[1:].strip()
            term_ok = match_packet_term(row, term, include_risk_text=include_risk_text)
            if negate:
                term_ok = not term_ok
            if not term_ok:
                matched = False
                break
        if matched:
            return True
    return False
