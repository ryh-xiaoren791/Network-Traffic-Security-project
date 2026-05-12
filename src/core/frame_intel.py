from __future__ import annotations

from collections.abc import Mapping, Sequence

from src.core.packet_inspection import decode_raw_bytes, extract_ascii


def usb_hid_key_text(modifier: int, keycode: int) -> str:
    key_map = {
        4: "a",
        5: "b",
        6: "c",
        7: "d",
        8: "e",
        9: "f",
        10: "g",
        11: "h",
        12: "i",
        13: "j",
        14: "k",
        15: "l",
        16: "m",
        17: "n",
        18: "o",
        19: "p",
        20: "q",
        21: "r",
        22: "s",
        23: "t",
        24: "u",
        25: "v",
        26: "w",
        27: "x",
        28: "y",
        29: "z",
        30: "1",
        31: "2",
        32: "3",
        33: "4",
        34: "5",
        35: "6",
        36: "7",
        37: "8",
        38: "9",
        39: "0",
        40: "\n",
        44: " ",
        45: "-",
        46: "=",
        47: "[",
        48: "]",
        49: "\\",
        51: ";",
        52: "'",
        53: "`",
        54: ",",
        55: ".",
        56: "/",
    }
    shifted = {
        "1": "!",
        "2": "@",
        "3": "#",
        "4": "$",
        "5": "%",
        "6": "^",
        "7": "&",
        "8": "*",
        "9": "(",
        "0": ")",
        "-": "_",
        "=": "+",
        "[": "{",
        "]": "}",
        "\\": "|",
        ";": ":",
        "'": '"',
        "`": "~",
        ",": "<",
        ".": ">",
        "/": "?",
    }
    char = key_map.get(int(keycode or 0), "")
    if not char:
        return ""
    if int(modifier or 0) & 0x22 or int(modifier or 0) & 0x02:
        return shifted.get(char, char.upper())
    return char


def extract_frame_intel(detail: Mapping[str, object]) -> dict[str, object]:
    raw_bytes = decode_raw_bytes(str(detail.get("raw_hex", "")))
    linktype = int(detail.get("linktype", 0) or 0)
    intel: dict[str, object] = {"kind": "", "summary": "", "fields": {}, "text": ""}
    if linktype == 249 and len(raw_bytes) >= 30:
        modifier = int(raw_bytes[27])
        keycode = int(raw_bytes[29])
        text = usb_hid_key_text(modifier, keycode)
        if text:
            intel["kind"] = "USB HID Keyboard"
            intel["text"] = text
            intel["summary"] = f"疑似USB键盘按键: {repr(text)}"
            intel["fields"] = {
                "modifier": f"0x{modifier:02x}",
                "keycode": f"0x{keycode:02x}",
                "decoded_key": text,
            }
            return intel
    ascii_text = extract_ascii(raw_bytes)
    printable = "".join(ch for ch in ascii_text if ch != ".")
    if len(printable) >= 4:
        intel["kind"] = "Printable Bytes"
        intel["summary"] = f"可见ASCII片段: {printable[:48]}"
        intel["text"] = printable[:96]
    return intel


def build_frame_ctf_clues(frames: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    if not frames:
        return []
    clues: list[dict[str, object]] = []
    hid_chars: list[str] = []
    hid_frame_ids: list[int] = []
    for row in frames:
        frame_id = int(row.get("id", 0) or 0)
        intel = extract_frame_intel(row)
        text = str(intel.get("text", "") or "")
        if intel.get("kind") == "USB HID Keyboard" and text:
            hid_chars.append(text)
            hid_frame_ids.append(frame_id)
    candidate_text = "".join(hid_chars).strip()
    if len(candidate_text) >= 6:
        clues.append(
            {
                "level": "高风险",
                "level_key": "high",
                "type": "USB键盘输入",
                "summary": f"疑似恢复到USB键盘输入: {candidate_text[:64]}",
                "filter": "查看通用帧(linktype=249)",
                "packet_id": 0,
                "frame_id": hid_frame_ids[0] if hid_frame_ids else 0,
                "target_kind": "frame",
                "detail": "检测到疑似 USB HID 键盘报文序列，已从键码中恢复出连续输入文本，可直接用于题目取证。",
            }
        )
    return clues


__all__ = ["build_frame_ctf_clues", "extract_frame_intel", "usb_hid_key_text"]
