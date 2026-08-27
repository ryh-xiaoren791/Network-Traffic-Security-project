from src.core.flow_view_models import (
    FLOW_ARTIFACT_LABEL_MAP,
    FLOW_DIRECTION_LABEL_MAP,
    artifact_formats,
    asset_detail_text,
    asset_tree_values,
    build_flow_analysis_tip,
    build_flow_window_title,
    candidate_detail_text,
    candidate_tree_values,
    object_detail_text,
    object_export_suffix,
    object_tree_values,
)


def test_build_flow_window_title_and_tip() -> None:
    title = build_flow_window_title(
        {"proto": "TCP", "src_ip": "10.0.0.1", "src_port": 1111, "dst_ip": "10.0.0.2", "dst_port": 80}
    )
    tip = build_flow_analysis_tip(
        8,
        {
            "segment_count": 3,
            "client_to_server": {"payload_size": 12},
            "server_to_client": {"payload_size": 34},
            "candidates": [1, 2],
            "assets": [1],
            "objects": [],
        },
    )
    assert "会话追踪 TCP 10.0.0.1:1111 <-> 10.0.0.2:80" == title
    assert "共 8 条" in tip
    assert "候选 2" in tip


def test_artifact_formats_and_label_maps() -> None:
    assert FLOW_DIRECTION_LABEL_MAP["仅C->S"] == "client_to_server"
    assert FLOW_ARTIFACT_LABEL_MAP["候选列表"] == "candidates"
    assert artifact_formats("candidates") == ["csv", "json", "txt"]
    assert artifact_formats("split_text") == ["txt", "json"]
    assert artifact_formats("interleaved") == ["txt", "bin", "base64", "json"]


def test_candidate_and_asset_helpers_render_preview_and_detail() -> None:
    candidate = {
        "encoding": "base64",
        "source_kind": "reassembled",
        "direction": "C->S",
        "decoded_text": "flag{demo}",
        "confidence": "high",
        "value": "ZmxhZ3tkZW1vfQ==",
        "packet_ids": (1, 2),
    }
    asset = {
        "asset_type": "http",
        "direction": "S->C",
        "name": "host",
        "value": "ctf.example.com",
        "confidence": "medium",
        "source_kind": "payload",
        "packet_ids": (3,),
    }
    assert candidate_tree_values(candidate) == ("base64", "reassembled", "C->S", "flag{demo}")
    assert "来源包: 1, 2" in candidate_detail_text(candidate)
    assert asset_tree_values(asset) == ("http", "S->C", "host", "ctf.example.com")
    assert "资产详情:" in asset_detail_text(asset)


def test_object_helpers_render_detail_and_suffix() -> None:
    row = {
        "object_type": "png",
        "direction": "双向",
        "offset": 120,
        "size": 512,
        "preview": "PNG...",
        "source_kind": "reassembled",
        "packet_ids": (9, 10),
    }
    assert object_tree_values(row) == ("png", "双向", 120, 512, "PNG...")
    assert "来源包: 9, 10" in object_detail_text(row)
    assert object_export_suffix("png") == ".png"
    assert object_export_suffix("unknown") == ".bin"
