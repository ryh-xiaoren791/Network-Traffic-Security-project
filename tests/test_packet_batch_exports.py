from pathlib import Path
from unittest.mock import Mock

from src.app.packet_batch_exports import (
    build_batch_export_audit_detail,
    build_batch_export_status,
    build_batch_export_status_done,
    build_batch_export_success_message,
    execute_packet_batch_export,
    export_action_formats,
    export_action_hint,
)


def test_export_action_formats_and_hints() -> None:
    assert export_action_formats("字段提取导出") == ["csv", "json", "txt"]
    assert export_action_formats("按流正文文件导出") == ["dir"]
    assert "五元组归并" in export_action_hint("按流重组导出")
    assert "完整筛选结果集" in export_action_hint("原始流量导出")


def test_execute_packet_batch_export_delegates_by_action() -> None:
    runtime = Mock()
    rows = [{"id": 1}]
    out = Path("out.csv")

    runtime.extract_packet_fields.return_value = [{"id": 1, "app_protocol": "HTTP"}]
    runtime.export_packet_fields.return_value = out
    path, count = execute_packet_batch_export(runtime, "字段提取导出", rows, out, "csv")
    assert path == out
    assert count == 1
    runtime.extract_packet_fields.assert_called_once_with(rows)
    runtime.export_packet_fields.assert_called_once()

    runtime = Mock()
    runtime.export_packet_flow_body_bundle.return_value = Path("bundle")
    path, count = execute_packet_batch_export(runtime, "按流正文文件导出", rows, Path("bundle"), "dir")
    assert path == Path("bundle")
    assert count == 1
    runtime.export_packet_flow_body_bundle.assert_called_once_with(rows, Path("bundle"))

    runtime = Mock()
    runtime.expand_packet_rows.return_value = [{"id": 1, "raw_hex": "00"}]
    runtime.export_packets.return_value = Path("traffic.pcap")
    path, count = execute_packet_batch_export(runtime, "原始流量导出", rows, Path("traffic.pcap"), "pcap")
    assert path == Path("traffic.pcap")
    assert count == 1
    runtime.expand_packet_rows.assert_called_once_with(rows)
    runtime.export_packets.assert_called_once()


def test_batch_export_message_builders() -> None:
    assert build_batch_export_status("当前页", "字段提取导出", "csv") == "批量导出处理中: 当前页 | 字段提取导出 | format=csv"
    assert "truncated=1" in build_batch_export_audit_detail("当前页", "候选字符串导出", "json", 10, 50, True)
    assert "已截断" in build_batch_export_status_done(10, 50, True)
    message = build_batch_export_success_message(Path("demo.csv"), 10, 50, True)
    assert "demo.csv" in message
    assert "注意：结果已按最大条数截断" in message
