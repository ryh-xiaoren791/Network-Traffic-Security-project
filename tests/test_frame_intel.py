from src.core.frame_intel import build_frame_ctf_clues, extract_frame_intel, usb_hid_key_text


def test_usb_hid_key_text_supports_shifted_characters() -> None:
    assert usb_hid_key_text(0x02, 30) == "!"
    assert usb_hid_key_text(0x00, 4) == "a"


def test_extract_frame_intel_decodes_usb_hid_keyboard_frame() -> None:
    raw_bytes = bytearray(30)
    raw_bytes[27] = 0x00
    raw_bytes[29] = 4
    intel = extract_frame_intel({"linktype": 249, "raw_hex": bytes(raw_bytes).hex()})
    assert intel["kind"] == "USB HID Keyboard"
    assert intel["text"] == "a"
    assert intel["fields"]["decoded_key"] == "a"


def test_extract_frame_intel_falls_back_to_printable_ascii() -> None:
    intel = extract_frame_intel({"linktype": 1, "raw_hex": b"flag{demo}".hex()})
    assert intel["kind"] == "Printable Bytes"
    assert "flag{demo}" in str(intel["summary"])


def test_build_frame_ctf_clues_merges_usb_input_sequence() -> None:
    frames = []
    for idx, keycode in enumerate([4, 5, 6, 7, 8, 9], start=1):
        raw_bytes = bytearray(30)
        raw_bytes[29] = keycode
        frames.append({"id": idx, "linktype": 249, "raw_hex": bytes(raw_bytes).hex()})
    clues = build_frame_ctf_clues(frames)
    assert len(clues) == 1
    clue = clues[0]
    assert clue["type"] == "USB键盘输入"
    assert clue["frame_id"] == 1
    assert "abcdef" in str(clue["summary"])
