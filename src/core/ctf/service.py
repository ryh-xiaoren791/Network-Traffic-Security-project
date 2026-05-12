from __future__ import annotations

import base64
import csv
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal


DirectionMode = Literal["interleaved", "client_to_server", "server_to_client", "split"]
RenderMode = Literal["ascii", "utf-8", "hex", "base64"]

_BASE32_PATTERN = re.compile(r"(?i)(?:^|[^A-Z2-7=])([A-Z2-7=]{8,})(?:[^A-Z2-7=]|$)")
_BASE64_PATTERN = re.compile(r"(?i)(?:^|[^A-Z0-9+/=])([A-Z0-9+/=]{12,})(?:[^A-Z0-9+/=]|$)")
_HEX_PATTERN = re.compile(r"(?i)(?:^|[^0-9A-F])([0-9A-F]{16,})(?:[^0-9A-F]|$)")


@dataclass(frozen=True)
class FlowSegment:
    packet_id: int
    ts: str
    direction: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    proto: str
    payload: bytes
    sequence: int | None
    order_index: int


@dataclass(frozen=True)
class CandidateHit:
    encoding: str
    value: str
    decoded_text: str
    source_kind: str
    direction: str
    packet_ids: tuple[int, ...]
    confidence: str


@dataclass(frozen=True)
class AssetHit:
    asset_type: str
    name: str
    value: str
    direction: str
    source_kind: str
    packet_ids: tuple[int, ...]
    confidence: str


@dataclass(frozen=True)
class CarvedObject:
    object_type: str
    direction: str
    source_kind: str
    offset: int
    size: int
    preview: str
    packet_ids: tuple[int, ...]
    data_base64: str


class FlowWorkbenchService:
    def decode_raw_bytes(self, raw_hex: str) -> bytes:
        text = str(raw_hex or "").strip()
        if not text:
            return b""
        try:
            return bytes.fromhex(text)
        except Exception:
            return b""

    def decode_payload_by_mode(self, payload: bytes, mode: str) -> str:
        normalized = str(mode or "").strip().lower()
        if not payload:
            return "(empty)"
        if normalized == "ascii":
            return self._wrap_text(self._extract_ascii(payload), width=120)
        if normalized == "utf-8":
            return self._wrap_text(payload.decode("utf-8", errors="replace"), width=120)
        if normalized == "base64":
            return self._wrap_text(base64.b64encode(payload).decode("ascii"), width=96)
        return self._format_hex_dump(payload)

    def analyze_flow(
        self,
        rows: list[dict],
        anchor_src: str,
        anchor_sport: int,
        direction_mode: DirectionMode = "interleaved",
    ) -> dict:
        segments = self.collect_segments(rows, anchor_src=anchor_src, anchor_sport=anchor_sport)
        client_segments = [segment for segment in segments if segment.direction == "C->S"]
        server_segments = [segment for segment in segments if segment.direction == "S->C"]
        client_payload = self._merge_direction_payload(client_segments)
        server_payload = self._merge_direction_payload(server_segments)
        interleaved_payload = self._merge_interleaved_payload(segments)
        candidates = self.extract_candidates(
            segments=segments,
            client_payload=client_payload,
            server_payload=server_payload,
            interleaved_payload=interleaved_payload,
        )
        assets = self.extract_assets(
            segments=segments,
            client_payload=client_payload,
            server_payload=server_payload,
            interleaved_payload=interleaved_payload,
        )
        objects = self.extract_carved_objects(
            client_payload=client_payload,
            server_payload=server_payload,
            interleaved_payload=interleaved_payload,
            analysis_segments=segments,
        )
        return {
            "direction_mode": direction_mode,
            "segment_count": len(segments),
            "client_to_server": {
                "label": "C->S",
                "payload_bytes": client_payload,
                "payload_size": len(client_payload),
                "packet_ids": [segment.packet_id for segment in client_segments],
            },
            "server_to_client": {
                "label": "S->C",
                "payload_bytes": server_payload,
                "payload_size": len(server_payload),
                "packet_ids": [segment.packet_id for segment in server_segments],
            },
            "interleaved": {
                "label": "双向交错",
                "payload_bytes": interleaved_payload,
                "payload_size": len(interleaved_payload),
                "packet_ids": [segment.packet_id for segment in segments],
            },
            "segments": [asdict(segment) | {"payload_hex": segment.payload.hex()} for segment in segments],
            "candidates": [asdict(hit) for hit in candidates],
            "assets": [asdict(hit) for hit in assets],
            "objects": [asdict(obj) for obj in objects],
        }

    def render_stream_text(
        self,
        analysis: dict,
        mode: RenderMode = "ascii",
        direction_mode: DirectionMode = "interleaved",
    ) -> str:
        selected = str(direction_mode or "interleaved").strip().lower()
        if selected == "client_to_server":
            payload = bytes(analysis["client_to_server"]["payload_bytes"])
            return self.decode_payload_by_mode(payload, mode)
        if selected == "server_to_client":
            payload = bytes(analysis["server_to_client"]["payload_bytes"])
            return self.decode_payload_by_mode(payload, mode)
        if selected == "split":
            client_text = self.decode_payload_by_mode(bytes(analysis["client_to_server"]["payload_bytes"]), mode)
            server_text = self.decode_payload_by_mode(bytes(analysis["server_to_client"]["payload_bytes"]), mode)
            return "\n".join(
                [
                    "[C->S Reassembled]",
                    client_text,
                    "",
                    "[S->C Reassembled]",
                    server_text,
                ]
            )
        return self._render_interleaved_segments(analysis=analysis, mode=mode)

    def export_flow_artifact(self, analysis: dict, output_path: Path, artifact: str, file_format: str) -> Path:
        normalized_artifact = str(artifact or "").strip().lower()
        normalized_format = str(file_format or "").strip().lower()
        if normalized_artifact == "candidates":
            return self._export_candidates(analysis["candidates"], output_path, normalized_format)
        if normalized_artifact == "segments":
            return self._export_segments(analysis["segments"], output_path, normalized_format)
        if normalized_artifact == "assets":
            return self._export_assets(analysis.get("assets", []), output_path, normalized_format)
        if normalized_artifact == "objects":
            return self._export_objects(analysis.get("objects", []), output_path, normalized_format)
        if normalized_artifact == "client_to_server":
            payload = bytes(analysis["client_to_server"]["payload_bytes"])
            return self._export_payload(payload, output_path, normalized_format)
        if normalized_artifact == "server_to_client":
            payload = bytes(analysis["server_to_client"]["payload_bytes"])
            return self._export_payload(payload, output_path, normalized_format)
        if normalized_artifact == "split_text":
            content = self.render_stream_text(analysis, mode="ascii", direction_mode="split")
            return self._write_text(output_path, content)
        payload = bytes(analysis["interleaved"]["payload_bytes"])
        return self._export_payload(payload, output_path, normalized_format)

    def export_carved_object(self, object_row: dict, output_path: Path) -> Path:
        encoded = str(object_row.get("data_base64", "") or "")
        raw_bytes = base64.b64decode(encoded) if encoded else b""
        output_path.write_bytes(raw_bytes)
        return output_path

    def collect_segments(self, rows: list[dict], anchor_src: str, anchor_sport: int) -> list[FlowSegment]:
        segments: list[FlowSegment] = []
        for index, row in enumerate(rows):
            packet_id = int(row.get("id", 0) or 0)
            raw_bytes = self.decode_raw_bytes(str(row.get("raw_hex", "")))
            payload, sequence = self._extract_transport_payload(raw_bytes)
            if not payload:
                continue
            src_ip = str(row.get("src_ip", "") or "")
            src_port = int(row.get("src_port", 0) or 0)
            direction = "C->S" if src_ip == anchor_src and src_port == int(anchor_sport or 0) else "S->C"
            segments.append(
                FlowSegment(
                    packet_id=packet_id,
                    ts=str(row.get("ts", "") or ""),
                    direction=direction,
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=str(row.get("dst_ip", "") or ""),
                    dst_port=int(row.get("dst_port", 0) or 0),
                    proto=str(row.get("proto", "") or "").upper(),
                    payload=payload,
                    sequence=sequence,
                    order_index=index,
                )
            )
        return segments

    def extract_candidates(
        self,
        segments: list[FlowSegment],
        client_payload: bytes,
        server_payload: bytes,
        interleaved_payload: bytes,
    ) -> list[CandidateHit]:
        hits: list[CandidateHit] = []
        hits.extend(self._extract_candidates_from_blob(client_payload, "C->S", "reassembled"))
        hits.extend(self._extract_candidates_from_blob(server_payload, "S->C", "reassembled"))
        hits.extend(self._extract_candidates_from_blob(interleaved_payload, "双向", "reassembled"))
        hits.extend(self._extract_fragmented_base32_candidates(segments))
        dedup: dict[tuple[str, str, str], CandidateHit] = {}
        for hit in hits:
            key = (hit.encoding, hit.direction, hit.value)
            current = dedup.get(key)
            if current is None or self._confidence_rank(hit.confidence) > self._confidence_rank(current.confidence):
                dedup[key] = hit
        ordered = list(dedup.values())
        ordered.sort(key=lambda item: (-self._confidence_rank(item.confidence), item.encoding, item.direction, item.value))
        return ordered[:120]

    def extract_assets(
        self,
        segments: list[FlowSegment],
        client_payload: bytes,
        server_payload: bytes,
        interleaved_payload: bytes,
    ) -> list[AssetHit]:
        hits: list[AssetHit] = []
        hits.extend(self._extract_assets_from_blob(client_payload, "C->S", "reassembled"))
        hits.extend(self._extract_assets_from_blob(server_payload, "S->C", "reassembled"))
        hits.extend(self._extract_modbus_assets(segments))
        dedup: dict[tuple[str, str, str, str], AssetHit] = {}
        for hit in hits:
            key = (hit.asset_type, hit.direction, hit.name, hit.value)
            current = dedup.get(key)
            if current is None or self._confidence_rank(hit.confidence) > self._confidence_rank(current.confidence):
                dedup[key] = hit
        ordered = list(dedup.values())
        ordered.sort(key=lambda item: (-self._confidence_rank(item.confidence), item.asset_type, item.name, item.value))
        return ordered[:120]

    def extract_carved_objects(
        self,
        client_payload: bytes,
        server_payload: bytes,
        interleaved_payload: bytes,
        analysis_segments: list[FlowSegment],
    ) -> list[CarvedObject]:
        packet_ids_by_direction = {
            "C->S": tuple(segment.packet_id for segment in analysis_segments if segment.direction == "C->S"),
            "S->C": tuple(segment.packet_id for segment in analysis_segments if segment.direction == "S->C"),
            "双向": tuple(segment.packet_id for segment in analysis_segments),
        }
        objects: list[CarvedObject] = []
        objects.extend(self._scan_carved_objects(client_payload, "C->S", "reassembled", packet_ids_by_direction["C->S"]))
        objects.extend(self._scan_carved_objects(server_payload, "S->C", "reassembled", packet_ids_by_direction["S->C"]))
        objects.extend(self._scan_carved_objects(interleaved_payload, "双向", "reassembled", packet_ids_by_direction["双向"]))
        dedup: dict[tuple[str, str, int, int], CarvedObject] = {}
        for obj in objects:
            key = (obj.object_type, obj.direction, obj.offset, obj.size)
            if key not in dedup:
                dedup[key] = obj
        ordered = list(dedup.values())
        ordered.sort(key=lambda item: (item.direction, item.offset, item.object_type))
        return ordered[:80]

    @staticmethod
    def _confidence_rank(level: str) -> int:
        mapping = {"high": 3, "medium": 2, "low": 1}
        return mapping.get(str(level or "").strip().lower(), 0)

    @staticmethod
    def _wrap_text(text: str, width: int) -> str:
        if not text:
            return ""
        lines: list[str] = []
        for raw_line in text.splitlines() or [text]:
            if not raw_line:
                lines.append("")
                continue
            for offset in range(0, len(raw_line), width):
                lines.append(raw_line[offset : offset + width])
        return "\n".join(lines)

    @staticmethod
    def _extract_ascii(raw_bytes: bytes) -> str:
        return "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in raw_bytes)

    def _format_hex_dump(self, raw_bytes: bytes) -> str:
        if not raw_bytes:
            return "(empty)"
        text = raw_bytes.hex()
        out: list[str] = []
        byte_index = 0
        for offset in range(0, len(text), 32):
            chunk = text[offset : offset + 32]
            pairs = [chunk[index : index + 2] for index in range(0, len(chunk), 2)]
            out.append(f"{byte_index:08X}  {' '.join(pairs)}")
            byte_index += len(pairs)
        return "\n".join(out)

    def _extract_transport_payload(self, raw_bytes: bytes) -> tuple[bytes, int | None]:
        if len(raw_bytes) < 20:
            return b"", None
        network_offset = 0
        ethertype = 0
        if len(raw_bytes) >= 14:
            possible_ethertype = int.from_bytes(raw_bytes[12:14], "big")
            if possible_ethertype in {0x0800, 0x86DD, 0x8100}:
                ethertype = possible_ethertype
                network_offset = 14
                if ethertype == 0x8100 and len(raw_bytes) >= 18:
                    ethertype = int.from_bytes(raw_bytes[16:18], "big")
                    network_offset = 18
        if network_offset == 0:
            version = raw_bytes[0] >> 4
            if version == 4:
                ethertype = 0x0800
            elif version == 6:
                ethertype = 0x86DD
            else:
                return b"", None
        if ethertype == 0x0800:
            if len(raw_bytes) < network_offset + 20:
                return b"", None
            ip_header_len = (raw_bytes[network_offset] & 0x0F) * 4
            if ip_header_len < 20 or len(raw_bytes) < network_offset + ip_header_len:
                return b"", None
            proto = raw_bytes[network_offset + 9]
            transport_offset = network_offset + ip_header_len
        elif ethertype == 0x86DD:
            if len(raw_bytes) < network_offset + 40:
                return b"", None
            proto = raw_bytes[network_offset + 6]
            transport_offset = network_offset + 40
        else:
            return b"", None
        if proto == 6:
            if len(raw_bytes) < transport_offset + 20:
                return b"", None
            tcp_header_len = ((raw_bytes[transport_offset + 12] >> 4) & 0x0F) * 4
            if tcp_header_len < 20 or len(raw_bytes) < transport_offset + tcp_header_len:
                return b"", None
            sequence = int.from_bytes(raw_bytes[transport_offset + 4 : transport_offset + 8], "big")
            payload_offset = transport_offset + tcp_header_len
            return raw_bytes[payload_offset:], sequence
        if proto == 17:
            if len(raw_bytes) < transport_offset + 8:
                return b"", None
            return raw_bytes[transport_offset + 8 :], None
        return b"", None

    def _merge_direction_payload(self, segments: list[FlowSegment]) -> bytes:
        if not segments:
            return b""
        proto = str(segments[0].proto or "").upper()
        if proto != "TCP":
            ordered = sorted(segments, key=lambda item: (item.order_index, item.packet_id))
            return b"".join(segment.payload for segment in ordered if segment.payload)
        ordered = sorted(
            segments,
            key=lambda item: (
                -1 if item.sequence is None else int(item.sequence),
                item.order_index,
                item.packet_id,
            ),
        )
        merged = bytearray()
        current_end: int | None = None
        for segment in ordered:
            if not segment.payload:
                continue
            if segment.sequence is None:
                merged.extend(segment.payload)
                continue
            segment_start = int(segment.sequence)
            if current_end is None:
                merged.extend(segment.payload)
                current_end = segment_start + len(segment.payload)
                continue
            if segment_start < current_end:
                overlap = current_end - segment_start
                if overlap >= len(segment.payload):
                    continue
                merged.extend(segment.payload[overlap:])
                current_end += len(segment.payload) - overlap
                continue
            if segment_start > current_end:
                merged.extend(segment.payload)
                current_end = segment_start + len(segment.payload)
                continue
            merged.extend(segment.payload)
            current_end += len(segment.payload)
        return bytes(merged)

    def _merge_interleaved_payload(self, segments: list[FlowSegment]) -> bytes:
        ordered = sorted(segments, key=lambda item: (item.order_index, item.packet_id))
        merged = bytearray()
        for segment in ordered:
            if segment.payload:
                merged.extend(segment.payload)
        return bytes(merged)

    def _render_interleaved_segments(self, analysis: dict, mode: str) -> str:
        lines: list[str] = []
        for index, row in enumerate(analysis["segments"], start=1):
            payload = bytes.fromhex(str(row.get("payload_hex", "") or ""))
            head = (
                f"[{index:04d}] {row.get('ts', '')} {row.get('direction', '')} "
                f"{row.get('src_ip', '')}:{row.get('src_port', 0)} -> {row.get('dst_ip', '')}:{row.get('dst_port', 0)} "
                f"LEN={len(payload)}"
            )
            lines.append(head)
            lines.append(self.decode_payload_by_mode(payload, mode))
            lines.append("")
        return "\n".join(lines).rstrip()

    def _extract_candidates_from_blob(self, blob: bytes, direction: str, source_kind: str) -> list[CandidateHit]:
        ascii_blob = self._extract_ascii(blob)
        hits: list[CandidateHit] = []
        hits.extend(self._regex_candidates(_BASE32_PATTERN, ascii_blob, "base32", direction, source_kind))
        hits.extend(self._regex_candidates(_BASE64_PATTERN, ascii_blob, "base64", direction, source_kind))
        hits.extend(self._regex_candidates(_HEX_PATTERN, ascii_blob, "hex", direction, source_kind))
        return hits

    def _extract_assets_from_blob(self, blob: bytes, direction: str, source_kind: str) -> list[AssetHit]:
        ascii_blob = blob.decode("utf-8", errors="replace")
        hits: list[AssetHit] = []
        for match in re.finditer(r"Host:\s*([A-Za-z0-9.-]+\.[A-Za-z]{2,})", ascii_blob, flags=re.IGNORECASE):
            host = str(match.group(1) or "").strip()
            hits.append(
                AssetHit(
                    asset_type="http_host",
                    name="HTTP Host",
                    value=host,
                    direction=direction,
                    source_kind=source_kind,
                    packet_ids=(),
                    confidence="medium",
                )
            )
        for match in re.finditer(r"([A-Za-z]{3,10}\s+(/[^\s]*)\s+HTTP/1\.[01])", ascii_blob):
            request_line = str(match.group(1) or "").strip()
            hits.append(
                AssetHit(
                    asset_type="http_request",
                    name="HTTP Request",
                    value=request_line,
                    direction=direction,
                    source_kind=source_kind,
                    packet_ids=(),
                    confidence="medium",
                )
            )
        for match in re.finditer(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{6,}", ascii_blob, flags=re.IGNORECASE):
            url = str(match.group(0) or "").strip().rstrip(").,;")
            hits.append(
                AssetHit(
                    asset_type="url",
                    name="URL",
                    value=url,
                    direction=direction,
                    source_kind=source_kind,
                    packet_ids=(),
                    confidence="medium",
                )
            )
        for match in re.finditer(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", ascii_blob):
            email = str(match.group(0) or "").strip()
            hits.append(
                AssetHit(
                    asset_type="email",
                    name="Email",
                    value=email,
                    direction=direction,
                    source_kind=source_kind,
                    packet_ids=(),
                    confidence="low",
                )
            )
        return hits

    def _extract_modbus_assets(self, segments: list[FlowSegment]) -> list[AssetHit]:
        hits: list[AssetHit] = []
        for segment in segments:
            parsed = self._parse_modbus_payload(segment.payload, segment.direction)
            if not parsed:
                continue
            target = str(parsed.get("target", "") or "").strip()
            value = f"{parsed.get('function_name', '')} | unit={parsed.get('unit_id', '-')}"
            if target:
                value = f"{value} | {target}"
            if parsed.get("exception_code"):
                value = f"{value} | exception={parsed.get('exception_code', '')}"
            hits.append(
                AssetHit(
                    asset_type="modbus",
                    name="Modbus/TCP",
                    value=value,
                    direction=segment.direction,
                    source_kind="segment",
                    packet_ids=(segment.packet_id,),
                    confidence="medium",
                )
            )
        return hits

    def _regex_candidates(
        self,
        pattern: re.Pattern[str],
        ascii_blob: str,
        encoding: str,
        direction: str,
        source_kind: str,
    ) -> list[CandidateHit]:
        hits: list[CandidateHit] = []
        for match in pattern.finditer(ascii_blob):
            value = str(match.group(1) or "").strip()
            if not value:
                continue
            decoded = self._decode_candidate(value, encoding)
            if decoded is None:
                continue
            hits.append(
                CandidateHit(
                    encoding=encoding,
                    value=value,
                    decoded_text=decoded,
                    source_kind=source_kind,
                    direction=direction,
                    packet_ids=(),
                    confidence="medium" if encoding != "hex" else "low",
                )
            )
        return hits

    def _extract_fragmented_base32_candidates(self, segments: list[FlowSegment]) -> list[CandidateHit]:
        hits: list[CandidateHit] = []
        for direction in ("C->S", "S->C"):
            current_parts: list[str] = []
            current_ids: list[int] = []
            last_order = -99
            for segment in segments:
                if segment.direction != direction:
                    continue
                token = self._project_alphabet(segment.payload, alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=")
                if token and len(token) <= 8:
                    if current_parts and segment.order_index - last_order > 3:
                        hits.extend(self._flush_fragmented_base32(current_parts, current_ids, direction))
                        current_parts = []
                        current_ids = []
                    current_parts.append(token)
                    current_ids.append(segment.packet_id)
                    last_order = segment.order_index
                    continue
                if current_parts:
                    hits.extend(self._flush_fragmented_base32(current_parts, current_ids, direction))
                    current_parts = []
                    current_ids = []
            if current_parts:
                hits.extend(self._flush_fragmented_base32(current_parts, current_ids, direction))
        return hits

    def _flush_fragmented_base32(self, parts: list[str], packet_ids: list[int], direction: str) -> list[CandidateHit]:
        value = "".join(parts).upper()
        if len(value) < 8:
            return []
        decoded = self._decode_candidate(value, "base32")
        if decoded is None:
            return []
        return [
            CandidateHit(
                encoding="base32",
                value=value,
                decoded_text=decoded,
                source_kind="fragmented",
                direction=direction,
                packet_ids=tuple(packet_ids),
                confidence="high",
            )
        ]

    @staticmethod
    def _project_alphabet(payload: bytes, alphabet: str) -> str:
        allowed = set(alphabet)
        chars = [chr(byte).upper() for byte in payload if 32 <= byte <= 126 and chr(byte).upper() in allowed]
        return "".join(chars)

    def _parse_modbus_payload(self, payload: bytes, direction: str) -> dict | None:
        if len(payload) < 8:
            return None
        protocol_id = int.from_bytes(payload[2:4], "big")
        if protocol_id != 0:
            return None
        unit_id = payload[6]
        func_code = payload[7]
        pdu = payload[8:]
        is_response = direction == "S->C"
        parsed: dict[str, str] = {
            "unit_id": str(unit_id),
            "function_code": f"0x{func_code:02x}",
            "function_name": self._modbus_function_name(func_code),
        }
        if func_code & 0x80:
            if pdu:
                parsed["exception_code"] = f"0x{pdu[0]:02x}"
            return parsed
        base_code = func_code & 0x7F
        if base_code in {1, 2, 3, 4}:
            if not is_response and len(pdu) >= 4:
                parsed["start_address"] = str(int.from_bytes(pdu[0:2], "big"))
                parsed["quantity"] = str(int.from_bytes(pdu[2:4], "big"))
            elif is_response and pdu:
                parsed["byte_count"] = str(pdu[0])
        elif base_code in {5, 6} and len(pdu) >= 4:
            parsed["address"] = str(int.from_bytes(pdu[0:2], "big"))
            parsed["value"] = f"0x{int.from_bytes(pdu[2:4], 'big'):04x}"
        elif base_code in {15, 16} and len(pdu) >= 4:
            parsed["start_address"] = str(int.from_bytes(pdu[0:2], "big"))
            parsed["quantity"] = str(int.from_bytes(pdu[2:4], "big"))
        if "start_address" in parsed and "quantity" in parsed:
            parsed["target"] = f"addr={parsed['start_address']} qty={parsed['quantity']}"
        elif "address" in parsed:
            parsed["target"] = f"addr={parsed['address']}"
        return parsed

    @staticmethod
    def _modbus_function_name(func_code: int) -> str:
        mapping = {
            1: "Read Coils",
            2: "Read Discrete Inputs",
            3: "Read Holding Registers",
            4: "Read Input Registers",
            5: "Write Single Coil",
            6: "Write Single Register",
            15: "Write Multiple Coils",
            16: "Write Multiple Registers",
        }
        base = int(func_code or 0) & 0x7F
        name = mapping.get(base, f"Function {base}")
        return f"{name} Exception" if int(func_code or 0) & 0x80 else name

    def _decode_candidate(self, value: str, encoding: str) -> str | None:
        try:
            if encoding == "base32":
                decoded = base64.b32decode(value.upper(), casefold=True)
            elif encoding == "base64":
                decoded = base64.b64decode(value, validate=False)
            elif encoding == "hex":
                decoded = bytes.fromhex(value)
            else:
                return None
        except Exception:
            return None
        return self._preview_bytes(decoded)

    def _preview_bytes(self, decoded: bytes) -> str:
        if not decoded:
            return "(empty)"
        try:
            text = decoded.decode("utf-8", errors="replace")
        except Exception:
            text = self._extract_ascii(decoded)
        compact = text.replace("\r", "\\r").replace("\n", "\\n")
        if len(compact) <= 160:
            return compact
        return compact[:160] + "..."

    def _scan_carved_objects(
        self,
        payload: bytes,
        direction: str,
        source_kind: str,
        packet_ids: tuple[int, ...],
    ) -> list[CarvedObject]:
        objects: list[CarvedObject] = []
        scanners = (
            ("png", b"\x89PNG\r\n\x1a\n", self._slice_png),
            ("zip", b"PK\x03\x04", self._slice_zip),
            ("gzip", b"\x1f\x8b\x08", self._slice_gzip),
            ("pdf", b"%PDF-", self._slice_pdf),
            ("jpeg", b"\xff\xd8\xff", self._slice_jpeg),
            ("gif", b"GIF8", self._slice_gif),
            ("pe", b"MZ", self._slice_pe),
            ("elf", b"\x7fELF", self._slice_elf),
        )
        for object_type, signature, slicer in scanners:
            start = 0
            while True:
                offset = payload.find(signature, start)
                if offset < 0:
                    break
                carved = slicer(payload, offset)
                if carved:
                    objects.append(
                        CarvedObject(
                            object_type=object_type,
                            direction=direction,
                            source_kind=source_kind,
                            offset=offset,
                            size=len(carved),
                            preview=self._preview_bytes(carved[:160]),
                            packet_ids=packet_ids[:24],
                            data_base64=base64.b64encode(carved).decode("ascii"),
                        )
                    )
                    start = offset + max(1, len(carved))
                    continue
                start = offset + len(signature)
        return objects

    @staticmethod
    def _slice_png(payload: bytes, offset: int) -> bytes:
        end = payload.find(b"IEND\xaeB`\x82", offset)
        if end < 0:
            return b""
        return payload[offset : end + 8]

    @staticmethod
    def _slice_zip(payload: bytes, offset: int) -> bytes:
        end = payload.find(b"PK\x05\x06", offset)
        if end < 0:
            return b""
        comment_len_offset = end + 20
        if comment_len_offset + 2 > len(payload):
            return b""
        comment_len = int.from_bytes(payload[comment_len_offset : comment_len_offset + 2], "little")
        final_end = end + 22 + comment_len
        if final_end > len(payload):
            return b""
        return payload[offset:final_end]

    @staticmethod
    def _slice_gzip(payload: bytes, offset: int) -> bytes:
        return payload[offset : min(len(payload), offset + 262144)]

    @staticmethod
    def _slice_pdf(payload: bytes, offset: int) -> bytes:
        end = payload.find(b"%%EOF", offset)
        if end < 0:
            return b""
        final_end = min(len(payload), end + 5)
        while final_end < len(payload) and payload[final_end : final_end + 1] in {b"\r", b"\n"}:
            final_end += 1
        return payload[offset:final_end]

    @staticmethod
    def _slice_jpeg(payload: bytes, offset: int) -> bytes:
        end = payload.find(b"\xff\xd9", offset + 2)
        if end < 0:
            return b""
        return payload[offset : end + 2]

    @staticmethod
    def _slice_gif(payload: bytes, offset: int) -> bytes:
        end = payload.find(b"\x3b", offset + 6)
        if end < 0:
            return b""
        return payload[offset : end + 1]

    @staticmethod
    def _slice_pe(payload: bytes, offset: int) -> bytes:
        return payload[offset : min(len(payload), offset + 262144)]

    @staticmethod
    def _slice_elf(payload: bytes, offset: int) -> bytes:
        return payload[offset : min(len(payload), offset + 262144)]

    def _export_candidates(self, candidates: list[dict], output_path: Path, file_format: str) -> Path:
        if file_format == "json":
            output_path.write_text(json.dumps(candidates, ensure_ascii=False, indent=2), encoding="utf-8")
            return output_path
        if file_format == "csv":
            fields = ["encoding", "value", "decoded_text", "source_kind", "direction", "packet_ids", "confidence"]
            with output_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=fields)
                writer.writeheader()
                for row in candidates:
                    writer.writerow({key: row.get(key, "") for key in fields})
            return output_path
        return self._write_text(
            output_path,
            "\n".join(
                f"[{item.get('confidence', '')}] {item.get('encoding', '')} {item.get('direction', '')} {item.get('value', '')} => {item.get('decoded_text', '')}"
                for item in candidates
            ),
        )

    def _export_segments(self, segments: list[dict], output_path: Path, file_format: str) -> Path:
        if file_format == "json":
            output_path.write_text(json.dumps(segments, ensure_ascii=False, indent=2), encoding="utf-8")
            return output_path
        if file_format == "csv":
            fields = ["packet_id", "ts", "direction", "src_ip", "src_port", "dst_ip", "dst_port", "proto", "payload_hex"]
            with output_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=fields)
                writer.writeheader()
                for row in segments:
                    writer.writerow({key: row.get(key, "") for key in fields})
            return output_path
        lines = []
        for index, row in enumerate(segments, start=1):
            lines.append(
                f"[{index:04d}] {row.get('ts', '')} {row.get('direction', '')} "
                f"{row.get('src_ip', '')}:{row.get('src_port', 0)} -> {row.get('dst_ip', '')}:{row.get('dst_port', 0)}"
            )
            lines.append(str(row.get("payload_hex", "")))
            lines.append("")
        return self._write_text(output_path, "\n".join(lines).rstrip())

    def _export_assets(self, assets: list[dict], output_path: Path, file_format: str) -> Path:
        if file_format == "json":
            output_path.write_text(json.dumps(assets, ensure_ascii=False, indent=2), encoding="utf-8")
            return output_path
        if file_format == "csv":
            fields = ["asset_type", "name", "value", "direction", "source_kind", "packet_ids", "confidence"]
            with output_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=fields)
                writer.writeheader()
                for row in assets:
                    writer.writerow({key: row.get(key, "") for key in fields})
            return output_path
        return self._write_text(
            output_path,
            "\n".join(
                f"[{item.get('asset_type', '')}] {item.get('direction', '')} {item.get('value', '')}"
                for item in assets
            ),
        )

    def _export_objects(self, objects: list[dict], output_path: Path, file_format: str) -> Path:
        if file_format == "json":
            output_path.write_text(json.dumps(objects, ensure_ascii=False, indent=2), encoding="utf-8")
            return output_path
        if file_format == "csv":
            fields = ["object_type", "direction", "source_kind", "offset", "size", "preview", "packet_ids"]
            with output_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=fields)
                writer.writeheader()
                for row in objects:
                    writer.writerow({key: row.get(key, "") for key in fields})
            return output_path
        return self._write_text(
            output_path,
            "\n".join(
                f"[{item.get('object_type', '')}] {item.get('direction', '')} offset={item.get('offset', 0)} size={item.get('size', 0)} {item.get('preview', '')}"
                for item in objects
            ),
        )

    def _export_payload(self, payload: bytes, output_path: Path, file_format: str) -> Path:
        if file_format == "bin":
            output_path.write_bytes(payload)
            return output_path
        if file_format == "json":
            output_path.write_text(
                json.dumps(
                    {
                        "size": len(payload),
                        "hex": payload.hex(),
                        "ascii": self._extract_ascii(payload),
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )
            return output_path
        if file_format == "base64":
            return self._write_text(output_path, base64.b64encode(payload).decode("ascii"))
        return self._write_text(output_path, self.decode_payload_by_mode(payload, "ascii"))

    @staticmethod
    def _write_text(output_path: Path, content: str) -> Path:
        output_path.write_text(content, encoding="utf-8")
        return output_path
