from __future__ import annotations

from collections.abc import Mapping


STREAM_MODE_OPTIONS = ("ascii", "utf-8", "hex", "base64")
FLOW_DIRECTION_LABEL_MAP = {
    "双向交错": "interleaved",
    "仅C->S": "client_to_server",
    "仅S->C": "server_to_client",
    "分方向重组": "split",
}
FLOW_ARTIFACT_LABEL_MAP = {
    "双向交错正文": "interleaved",
    "仅C->S正文": "client_to_server",
    "仅S->C正文": "server_to_client",
    "分方向文本": "split_text",
    "候选列表": "candidates",
    "资产列表": "assets",
    "对象列表": "objects",
    "分段明细": "segments",
}
OBJECT_EXPORT_SUFFIXES = {
    "png": ".png",
    "zip": ".zip",
    "gzip": ".gz",
    "pdf": ".pdf",
    "jpeg": ".jpg",
    "gif": ".gif",
    "pe": ".bin",
    "elf": ".bin",
}


def build_flow_window_title(first_row: Mapping[str, object]) -> str:
    return (
        f"会话追踪 {first_row.get('proto', '')} "
        f"{first_row.get('src_ip', '')}:{first_row.get('src_port', 0)} <-> "
        f"{first_row.get('dst_ip', '')}:{first_row.get('dst_port', 0)}"
    )


def build_flow_analysis_tip(row_count: int, analysis: Mapping[str, object]) -> str:
    client_to_server = dict(analysis.get("client_to_server", {}) or {})
    server_to_client = dict(analysis.get("server_to_client", {}) or {})
    return (
        f"共 {row_count} 条 | 有效负载分段 {analysis.get('segment_count', 0)} | "
        f"C->S {client_to_server.get('payload_size', 0)}B | "
        f"S->C {server_to_client.get('payload_size', 0)}B | "
        f"候选 {len(list(analysis.get('candidates', []) or []))} | "
        f"资产 {len(list(analysis.get('assets', []) or []))} | "
        f"对象 {len(list(analysis.get('objects', []) or []))}"
    )


def artifact_formats(artifact_key: str) -> list[str]:
    normalized = str(artifact_key or "").strip().lower()
    if normalized in {"candidates", "segments", "assets", "objects"}:
        return ["csv", "json", "txt"]
    if normalized == "split_text":
        return ["txt", "json"]
    return ["txt", "bin", "base64", "json"]


def candidate_tree_values(row: Mapping[str, object]) -> tuple[str, str, str, str]:
    return (
        str(row.get("encoding", "") or ""),
        str(row.get("source_kind", "") or ""),
        str(row.get("direction", "") or ""),
        str(row.get("decoded_text", "") or "")[:72],
    )


def candidate_detail_text(row: Mapping[str, object]) -> str:
    packet_ids = tuple(row.get("packet_ids", ()) or ())
    packet_text = ", ".join(str(pid) for pid in packet_ids[:16]) if packet_ids else "-"
    return "\n".join(
        [
            "候选详情:",
            f"- 编码: {row.get('encoding', '')} | 方向: {row.get('direction', '')} | 置信度: {row.get('confidence', '')}",
            f"- 来源: {row.get('source_kind', '')}",
            f"- 原文: {row.get('value', '')}",
            f"- 解码: {row.get('decoded_text', '')}",
            f"- 来源包: {packet_text}",
        ]
    )


def asset_tree_values(row: Mapping[str, object]) -> tuple[str, str, str, str]:
    return (
        str(row.get("asset_type", "") or ""),
        str(row.get("direction", "") or ""),
        str(row.get("name", "") or ""),
        str(row.get("value", "") or "")[:72],
    )


def asset_detail_text(row: Mapping[str, object]) -> str:
    packet_ids = tuple(row.get("packet_ids", ()) or ())
    packet_text = ", ".join(str(pid) for pid in packet_ids[:16]) if packet_ids else "-"
    return "\n".join(
        [
            "资产详情:",
            f"- 类型: {row.get('asset_type', '')} | 名称: {row.get('name', '')}",
            f"- 方向: {row.get('direction', '')} | 置信度: {row.get('confidence', '')}",
            f"- 来源: {row.get('source_kind', '')}",
            f"- 值: {row.get('value', '')}",
            f"- 来源包: {packet_text}",
        ]
    )


def object_tree_values(row: Mapping[str, object]) -> tuple[str, str, object, object, str]:
    return (
        str(row.get("object_type", "") or ""),
        str(row.get("direction", "") or ""),
        row.get("offset", 0),
        row.get("size", 0),
        str(row.get("preview", "") or "")[:56],
    )


def object_detail_text(row: Mapping[str, object]) -> str:
    packet_ids = tuple(row.get("packet_ids", ()) or ())
    packet_text = ", ".join(str(pid) for pid in packet_ids[:16]) if packet_ids else "-"
    return "\n".join(
        [
            "对象详情:",
            f"- 类型: {row.get('object_type', '')} | 方向: {row.get('direction', '')}",
            f"- 偏移: {row.get('offset', 0)} | 大小: {row.get('size', 0)} bytes",
            f"- 来源: {row.get('source_kind', '')}",
            f"- 预览: {row.get('preview', '')}",
            f"- 来源包: {packet_text}",
        ]
    )


def object_export_suffix(object_type: str) -> str:
    return OBJECT_EXPORT_SUFFIXES.get(str(object_type or "").strip().lower(), ".bin")


__all__ = [
    "FLOW_ARTIFACT_LABEL_MAP",
    "FLOW_DIRECTION_LABEL_MAP",
    "STREAM_MODE_OPTIONS",
    "artifact_formats",
    "asset_detail_text",
    "asset_tree_values",
    "build_flow_analysis_tip",
    "build_flow_window_title",
    "candidate_detail_text",
    "candidate_tree_values",
    "object_detail_text",
    "object_export_suffix",
    "object_tree_values",
]
