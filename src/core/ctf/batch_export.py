from __future__ import annotations

import base64
from collections import defaultdict
import csv
import json
import re
from pathlib import Path
from urllib.parse import unquote

from .service import FlowWorkbenchService


class PacketBatchExportService:
    def __init__(self) -> None:
        self.flow_service = FlowWorkbenchService()

    def extract_field_rows(self, packet_details: list[dict]) -> list[dict]:
        rows: list[dict] = []
        for detail in packet_details:
            raw_bytes = self.flow_service.decode_raw_bytes(str(detail.get("raw_hex", "") or ""))
            payload, _sequence = self.flow_service._extract_transport_payload(raw_bytes)  # internal helper reuse
            payload_ascii = self.flow_service._extract_ascii(payload) if payload else ""
            payload_preview = payload_ascii[:160]
            payload_hex_preview = payload[:64].hex() if payload else ""
            http_line = self._extract_http_line(payload)
            http_host = self._extract_http_host(payload)
            dns_qname = self._extract_dns_qname(payload, detail)
            tls_sni = self._extract_tls_sni(payload, detail)
            modbus_summary = self._extract_modbus_summary(payload, detail)
            rows.append(
                {
                    "id": int(detail.get("id", 0) or 0),
                    "ts": str(detail.get("ts", "") or ""),
                    "source": str(detail.get("source", "") or ""),
                    "risk_level": str(detail.get("risk_level", "") or ""),
                    "src_ip": str(detail.get("src_ip", "") or ""),
                    "src_port": int(detail.get("src_port", 0) or 0),
                    "dst_ip": str(detail.get("dst_ip", "") or ""),
                    "dst_port": int(detail.get("dst_port", 0) or 0),
                    "proto": str(detail.get("proto", "") or "").upper(),
                    "length": int(detail.get("length", 0) or 0),
                    "process_name": str(detail.get("process_name", "") or ""),
                    "app_protocol": self._infer_app_protocol(detail, payload, http_line, dns_qname, tls_sni, modbus_summary),
                    "http_request": http_line,
                    "http_host": http_host,
                    "dns_qname": dns_qname,
                    "tls_sni": tls_sni,
                    "modbus_summary": modbus_summary,
                    "payload_ascii_preview": payload_preview,
                    "payload_hex_preview": payload_hex_preview,
                }
            )
        return rows

    def export_field_rows(self, rows: list[dict], output_path: Path, file_format: str) -> Path:
        fmt = str(file_format or "").strip().lower()
        if fmt == "json":
            output_path.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
            return output_path
        if fmt == "csv":
            fields = [
                "id",
                "ts",
                "source",
                "risk_level",
                "src_ip",
                "src_port",
                "dst_ip",
                "dst_port",
                "proto",
                "length",
                "process_name",
                "app_protocol",
                "http_request",
                "http_host",
                "dns_qname",
                "tls_sni",
                "modbus_summary",
                "payload_ascii_preview",
                "payload_hex_preview",
            ]
            with output_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=fields)
                writer.writeheader()
                for row in rows:
                    writer.writerow({key: row.get(key, "") for key in fields})
            return output_path
        lines: list[str] = []
        for row in rows:
            lines.extend(
                [
                    f"[{row.get('id', 0)}] {row.get('ts', '')} {row.get('src_ip', '')}:{row.get('src_port', 0)} -> {row.get('dst_ip', '')}:{row.get('dst_port', 0)} {row.get('proto', '')}",
                    f"- 风险: {row.get('risk_level', '')} | 应用: {row.get('app_protocol', '')} | 进程: {row.get('process_name', '')}",
                    f"- HTTP: {row.get('http_request', '')} | Host: {row.get('http_host', '')}",
                    f"- DNS: {row.get('dns_qname', '')} | TLS SNI: {row.get('tls_sni', '')}",
                    f"- Modbus: {row.get('modbus_summary', '')}",
                    f"- Payload: {row.get('payload_ascii_preview', '')}",
                    "",
                ]
            )
        output_path.write_text("\n".join(lines).rstrip(), encoding="utf-8")
        return output_path

    def extract_flow_rows(self, packet_details: list[dict]) -> list[dict]:
        rows: list[dict] = []
        for flow_index, (flow_meta, flow_rows, analysis) in enumerate(self._build_flow_analyses(packet_details), start=1):
            best_candidate = analysis["candidates"][0] if analysis.get("candidates") else {}
            rows.append(
                {
                    "flow_index": flow_index,
                    "source": flow_meta["source"],
                    "proto": flow_meta["proto"],
                    "endpoint_a": flow_meta["endpoint_a"],
                    "endpoint_b": flow_meta["endpoint_b"],
                    "packet_count": len(flow_rows),
                    "segment_count": int(analysis.get("segment_count", 0) or 0),
                    "client_payload_size": int(analysis.get("client_to_server", {}).get("payload_size", 0) or 0),
                    "server_payload_size": int(analysis.get("server_to_client", {}).get("payload_size", 0) or 0),
                    "candidate_count": len(analysis.get("candidates", [])),
                    "asset_count": len(analysis.get("assets", [])),
                    "object_count": len(analysis.get("objects", [])),
                    "top_candidate_encoding": str(best_candidate.get("encoding", "") or ""),
                    "top_candidate_preview": str(best_candidate.get("decoded_text", "") or "")[:160],
                    "client_ascii_preview": self._preview_payload_ascii(bytes(analysis.get("client_to_server", {}).get("payload_bytes", b""))),
                    "server_ascii_preview": self._preview_payload_ascii(bytes(analysis.get("server_to_client", {}).get("payload_bytes", b""))),
                    "packet_ids": [int(row.get("id", 0) or 0) for row in flow_rows],
                }
            )
        return rows

    def export_flow_rows(self, rows: list[dict], output_path: Path, file_format: str) -> Path:
        fmt = str(file_format or "").strip().lower()
        if fmt == "json":
            output_path.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
            return output_path
        if fmt == "csv":
            fields = [
                "flow_index",
                "source",
                "proto",
                "endpoint_a",
                "endpoint_b",
                "packet_count",
                "segment_count",
                "client_payload_size",
                "server_payload_size",
                "candidate_count",
                "asset_count",
                "object_count",
                "top_candidate_encoding",
                "top_candidate_preview",
                "client_ascii_preview",
                "server_ascii_preview",
            ]
            with output_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=fields)
                writer.writeheader()
                for row in rows:
                    writer.writerow({key: row.get(key, "") for key in fields})
            return output_path
        lines: list[str] = []
        for row in rows:
            lines.extend(
                [
                    f"[FLOW {row.get('flow_index', 0)}] {row.get('proto', '')} {row.get('endpoint_a', '')} <-> {row.get('endpoint_b', '')} source={row.get('source', '')}",
                    f"- packets={row.get('packet_count', 0)} segments={row.get('segment_count', 0)} c2s={row.get('client_payload_size', 0)}B s2c={row.get('server_payload_size', 0)}B",
                    f"- candidates={row.get('candidate_count', 0)} assets={row.get('asset_count', 0)} objects={row.get('object_count', 0)}",
                    f"- top_candidate={row.get('top_candidate_encoding', '')} {row.get('top_candidate_preview', '')}",
                    f"- client_preview={row.get('client_ascii_preview', '')}",
                    f"- server_preview={row.get('server_ascii_preview', '')}",
                    "",
                ]
            )
        output_path.write_text("\n".join(lines).rstrip(), encoding="utf-8")
        return output_path

    def extract_candidate_rows(self, packet_details: list[dict]) -> list[dict]:
        rows: list[dict] = []
        for flow_index, (flow_meta, _flow_rows, analysis) in enumerate(self._build_flow_analyses(packet_details), start=1):
            for candidate in analysis.get("candidates", []):
                chain = self._decode_chain(str(candidate.get("value", "") or ""), str(candidate.get("encoding", "") or ""))
                rows.append(
                    {
                        "flow_index": flow_index,
                        "source": flow_meta["source"],
                        "proto": flow_meta["proto"],
                        "endpoint_a": flow_meta["endpoint_a"],
                        "endpoint_b": flow_meta["endpoint_b"],
                        "encoding": str(candidate.get("encoding", "") or ""),
                        "direction": str(candidate.get("direction", "") or ""),
                        "source_kind": str(candidate.get("source_kind", "") or ""),
                        "confidence": str(candidate.get("confidence", "") or ""),
                        "value": str(candidate.get("value", "") or ""),
                        "decoded_text": str(candidate.get("decoded_text", "") or ""),
                        "decode_chain": " -> ".join(chain["steps"]),
                        "final_preview": chain["final_preview"],
                        "packet_ids": list(candidate.get("packet_ids", ()) or []),
                    }
                )
        return rows

    def export_candidate_rows(self, rows: list[dict], output_path: Path, file_format: str) -> Path:
        fmt = str(file_format or "").strip().lower()
        if fmt == "json":
            output_path.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
            return output_path
        if fmt == "csv":
            fields = [
                "flow_index",
                "source",
                "proto",
                "endpoint_a",
                "endpoint_b",
                "encoding",
                "direction",
                "source_kind",
                "confidence",
                "value",
                "decoded_text",
                "decode_chain",
                "final_preview",
                "packet_ids",
            ]
            with output_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=fields)
                writer.writeheader()
                for row in rows:
                    writer.writerow({key: row.get(key, "") for key in fields})
            return output_path
        lines: list[str] = []
        for row in rows:
            lines.append(
                f"[FLOW {row.get('flow_index', 0)}] {row.get('encoding', '')} {row.get('direction', '')} {row.get('value', '')} => {row.get('decoded_text', '')} | chain={row.get('decode_chain', '')} | final={row.get('final_preview', '')}"
            )
        output_path.write_text("\n".join(lines).rstrip(), encoding="utf-8")
        return output_path

    def export_flow_body_bundle(self, packet_details: list[dict], output_dir: Path) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        index_rows: list[dict] = []
        for flow_index, (flow_meta, flow_rows, analysis) in enumerate(self._build_flow_analyses(packet_details), start=1):
            base_name = f"flow_{flow_index:03d}_{self._safe_name(flow_meta['proto'])}_{self._safe_name(flow_meta['endpoint_a'])}_to_{self._safe_name(flow_meta['endpoint_b'])}"
            interleaved_txt = output_dir / f"{base_name}_interleaved.txt"
            c2s_txt = output_dir / f"{base_name}_c2s.txt"
            s2c_txt = output_dir / f"{base_name}_s2c.txt"
            c2s_bin = output_dir / f"{base_name}_c2s.bin"
            s2c_bin = output_dir / f"{base_name}_s2c.bin"
            interleaved_txt.write_text(
                self.flow_service.render_stream_text(analysis, mode="ascii", direction_mode="interleaved"),
                encoding="utf-8",
            )
            c2s_txt.write_text(
                self.flow_service.render_stream_text(analysis, mode="ascii", direction_mode="client_to_server"),
                encoding="utf-8",
            )
            s2c_txt.write_text(
                self.flow_service.render_stream_text(analysis, mode="ascii", direction_mode="server_to_client"),
                encoding="utf-8",
            )
            c2s_bin.write_bytes(bytes(analysis.get("client_to_server", {}).get("payload_bytes", b"")))
            s2c_bin.write_bytes(bytes(analysis.get("server_to_client", {}).get("payload_bytes", b"")))
            index_rows.append(
                {
                    "flow_index": flow_index,
                    "source": flow_meta["source"],
                    "proto": flow_meta["proto"],
                    "endpoint_a": flow_meta["endpoint_a"],
                    "endpoint_b": flow_meta["endpoint_b"],
                    "packet_count": len(flow_rows),
                    "candidate_count": len(analysis.get("candidates", [])),
                    "asset_count": len(analysis.get("assets", [])),
                    "object_count": len(analysis.get("objects", [])),
                    "interleaved_file": interleaved_txt.name,
                    "client_text_file": c2s_txt.name,
                    "server_text_file": s2c_txt.name,
                    "client_bin_file": c2s_bin.name,
                    "server_bin_file": s2c_bin.name,
                }
            )
        (output_dir / "index.json").write_text(json.dumps(index_rows, ensure_ascii=False, indent=2), encoding="utf-8")
        return output_dir

    @staticmethod
    def _extract_http_line(payload: bytes) -> str:
        if not payload:
            return ""
        try:
            text = payload.decode("utf-8", errors="replace")
        except Exception:
            return ""
        first = text.splitlines()[0].strip() if text.splitlines() else ""
        if re.match(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+\S+\s+HTTP/1\.[01]$", first):
            return first
        return ""

    @staticmethod
    def _extract_http_host(payload: bytes) -> str:
        if not payload:
            return ""
        try:
            text = payload.decode("utf-8", errors="replace")
        except Exception:
            return ""
        match = re.search(r"Host:\s*([A-Za-z0-9.-]+\.[A-Za-z]{2,})", text, flags=re.IGNORECASE)
        return str(match.group(1) or "").strip() if match else ""

    @staticmethod
    def _extract_dns_qname(payload: bytes, detail: dict) -> str:
        src_port = int(detail.get("src_port", 0) or 0)
        dst_port = int(detail.get("dst_port", 0) or 0)
        if 53 not in {src_port, dst_port} or len(payload) < 13:
            return ""
        index = 12
        labels: list[str] = []
        try:
            while index < len(payload):
                length = payload[index]
                if length == 0:
                    break
                index += 1
                if length > 63 or index + length > len(payload):
                    return ""
                label = payload[index : index + length].decode("ascii", errors="ignore")
                if not label:
                    return ""
                labels.append(label)
                index += length
        except Exception:
            return ""
        return ".".join(labels)

    @staticmethod
    def _extract_tls_sni(payload: bytes, detail: dict) -> str:
        src_port = int(detail.get("src_port", 0) or 0)
        dst_port = int(detail.get("dst_port", 0) or 0)
        if 443 not in {src_port, dst_port} or len(payload) < 5:
            return ""
        try:
            text = payload.decode("utf-8", errors="ignore")
        except Exception:
            return ""
        match = re.search(r"([A-Za-z0-9.-]+\.[A-Za-z]{2,})", text)
        return str(match.group(1) or "").strip() if match else ""

    def _extract_modbus_summary(self, payload: bytes, detail: dict) -> str:
        ports = {int(detail.get("src_port", 0) or 0), int(detail.get("dst_port", 0) or 0)}
        if 502 not in ports:
            return ""
        direction = "S->C" if int(detail.get("src_port", 0) or 0) == 502 else "C->S"
        parsed = self.flow_service._parse_modbus_payload(payload, direction)  # internal helper reuse
        if not parsed:
            return ""
        summary = str(parsed.get("function_name", "") or "")
        target = str(parsed.get("target", "") or "")
        if target:
            summary = f"{summary} | {target}"
        if parsed.get("exception_code"):
            summary = f"{summary} | exception={parsed.get('exception_code', '')}"
        return summary

    @staticmethod
    def _infer_app_protocol(detail: dict, payload: bytes, http_line: str, dns_qname: str, tls_sni: str, modbus_summary: str) -> str:
        if http_line:
            return "HTTP"
        if dns_qname:
            return "DNS"
        if tls_sni:
            return "TLS"
        if modbus_summary:
            return "Modbus/TCP"
        proto = str(detail.get("proto", "") or "").upper()
        ports = {int(detail.get("src_port", 0) or 0), int(detail.get("dst_port", 0) or 0)}
        if proto == "UDP" and 443 in ports:
            return "QUIC"
        if proto == "ICMP":
            return "ICMP"
        if payload:
            return proto or "OTHER"
        return proto or "OTHER"

    def _build_flow_analyses(self, packet_details: list[dict]) -> list[tuple[dict, list[dict], dict]]:
        flow_map: dict[tuple[str, str, str, str], list[dict]] = defaultdict(list)
        for detail in packet_details:
            source = str(detail.get("source", "") or "")
            proto = str(detail.get("proto", "") or "").upper()
            left = f"{detail.get('src_ip', '')}:{int(detail.get('src_port', 0) or 0)}"
            right = f"{detail.get('dst_ip', '')}:{int(detail.get('dst_port', 0) or 0)}"
            endpoint_a, endpoint_b = sorted([left, right])
            flow_map[(source, proto, endpoint_a, endpoint_b)].append(detail)
        results: list[tuple[dict, list[dict], dict]] = []
        ordered_keys = sorted(flow_map.keys())
        for source, proto, endpoint_a, endpoint_b in ordered_keys:
            flow_rows = sorted(
                flow_map[(source, proto, endpoint_a, endpoint_b)],
                key=lambda row: (float(row.get("ts_epoch", 0.0) or 0.0), int(row.get("id", 0) or 0)),
            )
            if not flow_rows:
                continue
            anchor_src = str(flow_rows[0].get("src_ip", "") or "")
            anchor_sport = int(flow_rows[0].get("src_port", 0) or 0)
            analysis = self.flow_service.analyze_flow(flow_rows, anchor_src=anchor_src, anchor_sport=anchor_sport)
            results.append(
                (
                    {
                        "source": source,
                        "proto": proto,
                        "endpoint_a": endpoint_a,
                        "endpoint_b": endpoint_b,
                    },
                    flow_rows,
                    analysis,
                )
            )
        return results

    def _preview_payload_ascii(self, payload: bytes) -> str:
        if not payload:
            return ""
        preview = self.flow_service._extract_ascii(payload[:160])
        return preview[:160]

    def _decode_chain(self, value: str, encoding: str) -> dict:
        steps: list[str] = []
        current_bytes = self._decode_by_name(value, encoding)
        if current_bytes is None:
            return {"steps": [encoding], "final_preview": ""}
        steps.append(encoding)
        seen_texts: set[str] = set()
        for _ in range(3):
            text = self._bytes_to_text(current_bytes)
            compact = text.strip()
            if not compact or compact in seen_texts:
                break
            seen_texts.add(compact)
            next_encoding = self._detect_next_encoding(compact)
            if not next_encoding:
                return {"steps": steps, "final_preview": self._preview_text(compact)}
            next_bytes = self._decode_by_name(compact, next_encoding)
            if next_bytes is None:
                return {"steps": steps, "final_preview": self._preview_text(compact)}
            steps.append(next_encoding)
            current_bytes = next_bytes
        return {"steps": steps, "final_preview": self._preview_text(self._bytes_to_text(current_bytes))}

    def _detect_next_encoding(self, text: str) -> str:
        if "%" in text:
            decoded = unquote(text)
            if decoded != text:
                return "url"
        stripped = re.sub(r"\s+", "", text)
        if re.fullmatch(r"(?i)[A-Z2-7=]{8,}", stripped):
            return "base32"
        if re.fullmatch(r"(?i)[A-Z0-9+/=]{12,}", stripped):
            return "base64"
        if re.fullmatch(r"(?i)[0-9a-f]{16,}", stripped):
            return "hex"
        return ""

    def _decode_by_name(self, value: str, encoding: str) -> bytes | None:
        try:
            if encoding == "base32":
                return base64.b32decode(value.upper(), casefold=True)
            if encoding == "base64":
                return base64.b64decode(value, validate=False)
            if encoding == "hex":
                return bytes.fromhex(re.sub(r"\s+", "", value))
            if encoding == "url":
                return unquote(value).encode("utf-8", errors="replace")
        except Exception:
            return None
        return None

    @staticmethod
    def _bytes_to_text(raw: bytes) -> str:
        try:
            return raw.decode("utf-8", errors="replace")
        except Exception:
            return "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in raw)

    @staticmethod
    def _preview_text(text: str) -> str:
        compact = text.replace("\r", "\\r").replace("\n", "\\n")
        return compact[:160] + ("..." if len(compact) > 160 else "")

    @staticmethod
    def _safe_name(text: str) -> str:
        return re.sub(r"[^A-Za-z0-9._-]+", "_", str(text or "").strip("_") or "flow")
