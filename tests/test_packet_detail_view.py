from src.core.packet_detail_view import (
    PACKET_DETAIL_MODE_OPTIONS,
    build_expert_info_text,
    build_packet_detail_tree_nodes,
    build_packet_position_text,
    packet_app_headline,
)


def test_packet_detail_mode_options_and_position_text() -> None:
    assert PACKET_DETAIL_MODE_OPTIONS == ("hex", "ascii", "utf-8", "base64")
    detail = {"src_ip": "1.1.1.1", "src_port": 1234, "dst_ip": "2.2.2.2", "dst_port": 80, "proto": "TCP"}
    text = build_packet_position_text([10, 11, 12], 1, detail)
    assert text == "[2/3] ID=11  1.1.1.1:1234 -> 2.2.2.2:80  TCP"


def test_packet_app_headline_and_expert_text() -> None:
    assert packet_app_headline({"query": "flag.example"}) == "flag.example"
    assert packet_app_headline({}) == "-"
    content = build_expert_info_text(["first", "second"])
    assert content == "Expert Info:\n- first\n- second"


def test_build_packet_detail_tree_nodes_includes_protocol_and_security_sections() -> None:
    detail = {
        "id": 7,
        "ts": "2025-01-01 00:00:00",
        "length": 128,
        "source": "offline",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "src_port": 12345,
        "dst_port": 80,
        "proto": "TCP",
        "raw_hex": "00112233445566778899aabb08004500003c00010000400600000a0000010a0000023039005000000000000000005002200000000000474554202f20485454502f312e310d0a486f73743a206578616d706c652e636f6d0d0a0d0a",
    }
    alerts = [{"level": "medium", "sub_category": "web", "ts": "t1", "reason": "demo"}]
    nodes = build_packet_detail_tree_nodes(detail, "medium", alerts)
    top_texts = [node["text"] for node in nodes]
    assert top_texts[:3] == ["Frame", "Internet Protocol", "Transport (TCP)"]
    assert "Application (HTTP)" in top_texts
    assert top_texts[-1] == "Security"
    app_node = next(node for node in nodes if node["text"] == "Application (HTTP)")
    app_child_texts = [child["text"] for child in app_node["children"]]
    assert "First Line" in app_child_texts
    security_node = nodes[-1]
    assert security_node["value"] == "Risk=medium"
    assert security_node["children"][0]["text"] == "Related Alerts"
