from __future__ import annotations

from collections.abc import Mapping, Sequence

from src.core.packet_inspection import dissect_packet_bytes, extract_app_fields


PACKET_DETAIL_MODE_OPTIONS = ("hex", "ascii", "utf-8", "base64")


def packet_app_headline(app_fields: Mapping[str, object]) -> str:
    return str(
        app_fields.get("first_line")
        or app_fields.get("query")
        or app_fields.get("sni")
        or app_fields.get("handshake")
        or app_fields.get("function_name")
        or "-"
    )


def build_packet_position_text(packet_ids: Sequence[int], index: int, detail: Mapping[str, object]) -> str:
    packet_id = int(packet_ids[index])
    return (
        f"[{index + 1}/{len(packet_ids)}] ID={packet_id}  "
        f"{detail.get('src_ip', '')}:{detail.get('src_port', 0)} -> "
        f"{detail.get('dst_ip', '')}:{detail.get('dst_port', 0)}  "
        f"{detail.get('proto', '')}"
    )


def build_expert_info_text(findings: Sequence[str]) -> str:
    return "\n".join(["Expert Info:"] + [f"- {line}" for line in findings])


def build_packet_detail_tree_nodes(detail: Mapping[str, object], risk_value: str, alerts: Sequence[Mapping[str, object]]) -> list[dict]:
    layers = dissect_packet_bytes(detail)
    proto = str(detail.get("proto", "") or "").upper()
    app_proto, app_fields = extract_app_fields(detail)

    frame_children = [
        {"text": "Length", "value": str(detail.get("length", 0)), "children": []},
        {"text": "Source", "value": str(detail.get("source", "")), "children": []},
    ]
    if layers.get("src_mac") or layers.get("dst_mac"):
        frame_children.append(
            {
                "text": "Ethernet",
                "value": f"{layers.get('src_mac', '')} -> {layers.get('dst_mac', '')}",
                "children": [],
            }
        )
    if int(layers.get("ethertype", 0) or 0) > 0:
        frame_children.append({"text": "Ethertype", "value": f"0x{int(layers.get('ethertype', 0)):04x}", "children": []})

    nodes = [
        {
            "text": "Frame",
            "value": f"ID={detail.get('id')}  TIME={detail.get('ts', '')}",
            "children": frame_children,
            "open": True,
        },
        {
            "text": "Internet Protocol",
            "value": f"{detail.get('src_ip', '')} -> {detail.get('dst_ip', '')}",
            "children": [
                {"text": "Source IP", "value": str(detail.get("src_ip", "")), "children": []},
                {"text": "Destination IP", "value": str(detail.get("dst_ip", "")), "children": []},
            ],
            "open": True,
        },
    ]

    transport_children = [
        {"text": "Source Port", "value": str(detail.get("src_port", 0)), "children": []},
        {"text": "Destination Port", "value": str(detail.get("dst_port", 0)), "children": []},
    ]
    if proto == "TCP" and layers.get("tcp_flags"):
        transport_children.append({"text": "TCP Flags", "value": str(layers.get("tcp_flags", "")), "children": []})
    nodes.append(
        {
            "text": f"Transport ({proto or 'OTHER'})",
            "value": f"{detail.get('src_port', 0)} -> {detail.get('dst_port', 0)}",
            "children": transport_children,
            "open": True,
        }
    )

    if app_proto:
        nodes.append(
            {
                "text": f"Application ({app_proto})",
                "value": packet_app_headline(app_fields),
                "children": [
                    {
                        "text": str(key).replace("_", " ").title(),
                        "value": str(value),
                        "children": [],
                    }
                    for key, value in app_fields.items()
                ],
                "open": True,
            }
        )

    security_children = [{"text": "Related Alerts", "value": str(len(alerts)), "children": []}]
    security_children.extend(
        {
            "text": f"[{row.get('level', '')}] {row.get('sub_category', '')}",
            "value": f"{row.get('ts', '')} {row.get('reason', '')}",
            "children": [],
        }
        for row in alerts[:8]
    )
    nodes.append(
        {
            "text": "Security",
            "value": f"Risk={risk_value}",
            "children": security_children,
            "open": True,
        }
    )
    return nodes


__all__ = [
    "PACKET_DETAIL_MODE_OPTIONS",
    "build_expert_info_text",
    "build_packet_detail_tree_nodes",
    "build_packet_position_text",
    "packet_app_headline",
]
