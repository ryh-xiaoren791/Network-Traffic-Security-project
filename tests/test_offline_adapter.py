from src.core.offline.adapter import LegacyPacketBatchView, _native_batch_to_legacy_columns


def test_native_batch_to_legacy_columns_fills_missing_fields() -> None:
    columns, row_count = _native_batch_to_legacy_columns(
        {
            "ts": [1.25],
            "src_ip": ["10.0.0.1"],
            "dst_ip": ["10.0.0.2"],
            "raw_hex": ["001122334455"],
        },
        raw_hex_preview_bytes=2,
    )
    assert row_count == 1
    assert columns["raw_hex"] == ["0011"]
    assert columns["proto"] == [""]
    assert columns["length"] == [0]


def test_legacy_packet_batch_view_exposes_column_backed_rows() -> None:
    view = LegacyPacketBatchView(
        {
            "src_ip": ["10.0.0.1", "10.0.0.2"],
            "dst_ip": ["10.0.0.3", "10.0.0.4"],
        },
        row_count=2,
    )
    assert len(view) == 2
    assert view[0]["src_ip"] == "10.0.0.1"
    assert list(view.iter_rows())[1]["dst_ip"] == "10.0.0.4"
