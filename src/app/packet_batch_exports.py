from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path


BATCH_EXPORT_ACTION_CONFIG: dict[str, dict[str, object]] = {
    "原始流量导出": {
        "key": "raw_packets",
        "formats": ["pcap", "csv", "json"],
        "hint": "原始流量导出支持当前选中、当前页或完整筛选结果集。",
    },
    "字段提取导出": {
        "key": "field_rows",
        "formats": ["csv", "json", "txt"],
        "hint": "字段提取会批量解析 HTTP/DNS/TLS/Modbus 与载荷预览，适合拼接和检索。",
    },
    "按流重组导出": {
        "key": "flow_rows",
        "formats": ["csv", "json", "txt"],
        "hint": "按流重组会把当前结果按五元组归并，输出每条流的双向摘要与预览。",
    },
    "候选字符串导出": {
        "key": "candidate_rows",
        "formats": ["csv", "json", "txt"],
        "hint": "候选字符串导出会批量扫描每条流中的 Base32/Base64/Hex 等候选结果，并自动尝试二次解码链。",
    },
    "按流正文文件导出": {
        "key": "flow_body_bundle",
        "formats": ["dir"],
        "hint": "按流正文文件导出会为每条流生成双向文本和二进制正文文件，并附带 index 清单。",
    },
}


def export_action_formats(action_label: str) -> list[str]:
    config = BATCH_EXPORT_ACTION_CONFIG.get(str(action_label or "").strip(), BATCH_EXPORT_ACTION_CONFIG["原始流量导出"])
    return list(config["formats"])


def export_action_hint(action_label: str) -> str:
    config = BATCH_EXPORT_ACTION_CONFIG.get(str(action_label or "").strip(), BATCH_EXPORT_ACTION_CONFIG["原始流量导出"])
    return str(config["hint"])


def execute_packet_batch_export(runtime, action_label: str, rows: list[dict], output_path: Path, file_format: str) -> tuple[Path, int]:
    action_key = str(BATCH_EXPORT_ACTION_CONFIG.get(str(action_label or "").strip(), BATCH_EXPORT_ACTION_CONFIG["原始流量导出"])["key"])
    fmt = str(file_format or "").strip().lower()
    export_rows = rows
    if action_key == "field_rows":
        export_rows = runtime.extract_packet_fields(rows)
        return runtime.export_packet_fields(export_rows, output_path, fmt), len(export_rows)
    if action_key == "flow_rows":
        export_rows = runtime.extract_packet_flows(rows)
        return runtime.export_packet_flows(export_rows, output_path, fmt), len(export_rows)
    if action_key == "candidate_rows":
        export_rows = runtime.extract_packet_candidates(rows)
        return runtime.export_packet_candidates(export_rows, output_path, fmt), len(export_rows)
    if action_key == "flow_body_bundle":
        out_path = runtime.export_packet_flow_body_bundle(rows, output_path)
        return out_path, 1
    if fmt == "pcap":
        export_rows = runtime.expand_packet_rows(rows)
    return runtime.export_packets(export_rows, output_path, fmt), len(export_rows)


def build_batch_export_status(scope_label: str, action_label: str, file_format: str) -> str:
    return f"批量导出处理中: {scope_label} | {action_label} | format={str(file_format or '').strip().lower()}"


def build_batch_export_audit_detail(scope_label: str, action_label: str, file_format: str, exported_rows: int, total: int, truncated: bool) -> str:
    return (
        f"scope={scope_label},action={action_label},format={str(file_format or '').strip().lower()},"
        f"rows={int(exported_rows)},total={int(total)},truncated={int(bool(truncated))}"
    )


def build_batch_export_status_done(exported_rows: int, total: int, truncated: bool) -> str:
    total_suffix = f" / 命中总数 {int(total)}" if int(total or 0) else ""
    truncated_suffix = " (已截断)" if bool(truncated) else ""
    return f"批量导出完成: 已导出 {int(exported_rows)} 条{total_suffix}{truncated_suffix}"


def build_batch_export_success_message(output_path: Path, exported_rows: int, total: int, truncated: bool) -> str:
    suffix = "\n注意：结果已按最大条数截断。" if bool(truncated) else ""
    return f"导出成功:\n{output_path}\n\n已导出 {int(exported_rows)} 条，命中总数 {int(total)}。{suffix}"


__all__ = [
    "BATCH_EXPORT_ACTION_CONFIG",
    "build_batch_export_audit_detail",
    "build_batch_export_status",
    "build_batch_export_status_done",
    "build_batch_export_success_message",
    "execute_packet_batch_export",
    "export_action_formats",
    "export_action_hint",
]
