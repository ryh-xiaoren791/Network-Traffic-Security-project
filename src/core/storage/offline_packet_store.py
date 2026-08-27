from __future__ import annotations

import os
from pathlib import Path


class OfflinePacketStore:
    OFFLINE_ID_BASE = 10_000_000_000
    OFFLINE_FRAME_ID_BASE = 20_000_000_000

    def __init__(self, db_path: Path) -> None:
        import duckdb

        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = duckdb.connect(str(self.db_path))
        # 安全：值为 CPU 数（非用户输入），无注入面
        self.conn.execute(f"PRAGMA threads={max(1, int(os.cpu_count() or 1))};")  # nosec
        self.conn.execute("PRAGMA memory_limit='3072MB';")
        self._in_bulk = False
        self._index_suspended = False
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.execute(
            """
            CREATE SEQUENCE IF NOT EXISTS offline_packets_id_seq START 1;
            """
        )
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS offline_packets (
                id BIGINT DEFAULT nextval('offline_packets_id_seq'),
                ts DOUBLE,
                src_ip VARCHAR,
                dst_ip VARCHAR,
                src_port INTEGER,
                dst_port INTEGER,
                proto VARCHAR,
                length INTEGER,
                direction VARCHAR,
                process_id INTEGER,
                process_name VARCHAR,
                raw_hex VARCHAR,
                source VARCHAR
            );
            """
        )
        self.conn.execute(
            """
            CREATE SEQUENCE IF NOT EXISTS offline_frames_id_seq START 1;
            """
        )
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS offline_frames (
                id BIGINT DEFAULT nextval('offline_frames_id_seq'),
                frame_no BIGINT,
                ts DOUBLE,
                linktype INTEGER,
                iface VARCHAR,
                frame_type VARCHAR,
                caplen INTEGER,
                wirelen INTEGER,
                summary VARCHAR,
                raw_hex VARCHAR,
                source VARCHAR
            );
            """
        )
        self._ensure_indexes()

    def _ensure_indexes(self) -> None:
        if self._index_suspended:
            return
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_offline_packets_source_id ON offline_packets(source, id);")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_offline_packets_src_ip ON offline_packets(src_ip);")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_offline_packets_dst_ip ON offline_packets(dst_ip);")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_offline_packets_proto ON offline_packets(proto);")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_offline_frames_source_id ON offline_frames(source, id);")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_offline_frames_linktype ON offline_frames(linktype);")

    @classmethod
    def _encode_id(cls, real_id: int) -> int:
        return int(real_id) + cls.OFFLINE_ID_BASE

    @classmethod
    def _decode_id(cls, packet_id: int) -> int:
        value = int(packet_id)
        if value >= cls.OFFLINE_ID_BASE:
            return value - cls.OFFLINE_ID_BASE
        return -1

    @classmethod
    def _encode_frame_id(cls, real_id: int) -> int:
        return int(real_id) + cls.OFFLINE_FRAME_ID_BASE

    @classmethod
    def _decode_frame_id(cls, frame_id: int) -> int:
        value = int(frame_id)
        if value >= cls.OFFLINE_FRAME_ID_BASE:
            return value - cls.OFFLINE_FRAME_ID_BASE
        return -1

    def clear_source(self, source: str = "offline") -> int:
        if source == "offline":
            self.conn.execute("DROP TABLE IF EXISTS offline_packets")
            self.conn.execute("DROP SEQUENCE IF EXISTS offline_packets_id_seq")
            self.conn.execute("DROP TABLE IF EXISTS offline_frames")
            self.conn.execute("DROP SEQUENCE IF EXISTS offline_frames_id_seq")
            self._init_schema()
            return 0
        before = self.conn.execute("SELECT COUNT(*) FROM offline_packets WHERE source = ?", [source]).fetchone()[0]
        self.conn.execute("DELETE FROM offline_packets WHERE source = ?", [source])
        self.conn.execute("DELETE FROM offline_frames WHERE source = ?", [source])
        return int(before or 0)

    def begin_bulk(self) -> None:
        if self._in_bulk:
            return
        self._index_suspended = True
        self.conn.execute("DROP INDEX IF EXISTS idx_offline_packets_source_id")
        self.conn.execute("DROP INDEX IF EXISTS idx_offline_packets_src_ip")
        self.conn.execute("DROP INDEX IF EXISTS idx_offline_packets_dst_ip")
        self.conn.execute("DROP INDEX IF EXISTS idx_offline_packets_proto")
        self.conn.execute("DROP INDEX IF EXISTS idx_offline_frames_source_id")
        self.conn.execute("DROP INDEX IF EXISTS idx_offline_frames_linktype")
        self.conn.execute("BEGIN TRANSACTION")
        self._in_bulk = True

    def end_bulk(self) -> None:
        if not self._in_bulk:
            return
        self.conn.execute("COMMIT")
        self._in_bulk = False
        self._index_suspended = False
        self._ensure_indexes()

    def insert_rows(self, rows: list[tuple]) -> None:
        if not rows:
            return
        # Arrow批量路径比executemany更适合百万级导入。
        import pyarrow as pa

        cols = {
            "ts": [],
            "src_ip": [],
            "dst_ip": [],
            "src_port": [],
            "dst_port": [],
            "proto": [],
            "length": [],
            "direction": [],
            "process_id": [],
            "process_name": [],
            "raw_hex": [],
            "source": [],
        }
        for row in rows:
            cols["ts"].append(float(row[0] or 0.0))
            cols["src_ip"].append(str(row[1] or ""))
            cols["dst_ip"].append(str(row[2] or ""))
            cols["src_port"].append(int(row[3] or 0))
            cols["dst_port"].append(int(row[4] or 0))
            cols["proto"].append(str(row[5] or "OTHER"))
            cols["length"].append(int(row[6] or 0))
            cols["direction"].append(str(row[7] or "offline"))
            cols["process_id"].append(int(row[8] or 0))
            cols["process_name"].append(str(row[9] or ""))
            cols["raw_hex"].append(str(row[10] or ""))
            cols["source"].append(str(row[11] or "offline"))
        table = pa.table(cols)
        self.conn.register("_packet_batch_arrow", table)
        self.conn.execute(
            """
            INSERT INTO offline_packets(ts, src_ip, dst_ip, src_port, dst_port, proto, length, direction, process_id, process_name, raw_hex, source)
            SELECT ts, src_ip, dst_ip, src_port, dst_port, proto, length, direction, process_id, process_name, raw_hex, source
            FROM _packet_batch_arrow
            """,
        )
        self.conn.unregister("_packet_batch_arrow")

    def insert_legacy_batch(self, packets: object, preview_bytes: int, store_raw_hex: bool, source: str = "offline") -> None:
        import pyarrow as pa

        row_count = int(getattr(packets, "row_count", 0) or 0)
        if row_count <= 0:
            return
        get_col = getattr(packets, "get_column")
        ts_col = get_col("ts") or []
        src_ip_col = get_col("src_ip") or []
        dst_ip_col = get_col("dst_ip") or []
        src_port_col = get_col("src_port") or []
        dst_port_col = get_col("dst_port") or []
        proto_col = get_col("proto") or []
        len_col = get_col("length") or []
        direction_col = get_col("direction") or []
        process_id_col = get_col("process_id") or []
        process_name_col = get_col("process_name") or []
        raw_hex_col = get_col("raw_hex") or []
        max_hex = max(0, int(preview_bytes)) * 2

        def _pick(col: list, idx: int, default):
            return col[idx] if idx < len(col) else default

        ts_vals = [float(_pick(ts_col, i, 0.0) or 0.0) for i in range(row_count)]
        src_ip_vals = [str(_pick(src_ip_col, i, "")) for i in range(row_count)]
        dst_ip_vals = [str(_pick(dst_ip_col, i, "")) for i in range(row_count)]
        src_port_vals = [int(_pick(src_port_col, i, 0) or 0) for i in range(row_count)]
        dst_port_vals = [int(_pick(dst_port_col, i, 0) or 0) for i in range(row_count)]
        proto_vals = [str(_pick(proto_col, i, "OTHER")) for i in range(row_count)]
        len_vals = [int(_pick(len_col, i, 0) or 0) for i in range(row_count)]
        direction_vals = [str(_pick(direction_col, i, "offline")) for i in range(row_count)]
        pid_vals = [int(_pick(process_id_col, i, 0) or 0) for i in range(row_count)]
        pname_vals = [str(_pick(process_name_col, i, "")) for i in range(row_count)]
        if store_raw_hex:
            if max_hex > 0:
                raw_hex_vals = [str(_pick(raw_hex_col, i, ""))[:max_hex] for i in range(row_count)]
            else:
                raw_hex_vals = [str(_pick(raw_hex_col, i, "")) for i in range(row_count)]
        else:
            raw_hex_vals = [""] * row_count
        source_vals = [source] * row_count

        table = pa.table(
            {
                "ts": ts_vals,
                "src_ip": src_ip_vals,
                "dst_ip": dst_ip_vals,
                "src_port": src_port_vals,
                "dst_port": dst_port_vals,
                "proto": proto_vals,
                "length": len_vals,
                "direction": direction_vals,
                "process_id": pid_vals,
                "process_name": pname_vals,
                "raw_hex": raw_hex_vals,
                "source": source_vals,
            }
        )
        self.conn.register("_packet_batch_arrow", table)
        self.conn.execute(
            """
            INSERT INTO offline_packets(ts, src_ip, dst_ip, src_port, dst_port, proto, length, direction, process_id, process_name, raw_hex, source)
            SELECT ts, src_ip, dst_ip, src_port, dst_port, proto, length, direction, process_id, process_name, raw_hex, source
            FROM _packet_batch_arrow
            """
        )
        self.conn.unregister("_packet_batch_arrow")

    def insert_frame_batch(self, frames: list[dict], preview_bytes: int, source: str = "offline") -> None:
        if not frames:
            return
        import pyarrow as pa

        max_hex = max(0, int(preview_bytes)) * 2
        cols = {
            "frame_no": [],
            "ts": [],
            "linktype": [],
            "iface": [],
            "frame_type": [],
            "caplen": [],
            "wirelen": [],
            "summary": [],
            "raw_hex": [],
            "source": [],
        }
        for row in frames:
            cols["frame_no"].append(int(row.get("frame_no", 0) or 0))
            cols["ts"].append(float(row.get("ts", 0.0) or 0.0))
            cols["linktype"].append(int(row.get("linktype", 0) or 0))
            cols["iface"].append(str(row.get("iface", "") or ""))
            cols["frame_type"].append(str(row.get("frame_type", "") or "unknown"))
            cols["caplen"].append(int(row.get("caplen", 0) or 0))
            cols["wirelen"].append(int(row.get("wirelen", 0) or 0))
            cols["summary"].append(str(row.get("summary", "") or "")[:260])
            raw_hex = str(row.get("raw_hex", "") or "")
            cols["raw_hex"].append(raw_hex[:max_hex] if max_hex > 0 else raw_hex)
            cols["source"].append(str(row.get("source", source) or source))
        table = pa.table(cols)
        self.conn.register("_frame_batch_arrow", table)
        self.conn.execute(
            """
            INSERT INTO offline_frames(frame_no, ts, linktype, iface, frame_type, caplen, wirelen, summary, raw_hex, source)
            SELECT frame_no, ts, linktype, iface, frame_type, caplen, wirelen, summary, raw_hex, source
            FROM _frame_batch_arrow
            """
        )
        self.conn.unregister("_frame_batch_arrow")

    def query_packets(
        self,
        limit: int | None,
        offset: int = 0,
        process_name: str = "",
        ip: str = "",
        source: str = "offline",
        extra_sql: str = "",
        extra_args: list | None = None,
        sort_key: str = "ts",
        sort_desc: bool = True,
    ) -> list[dict]:
        sort_field = self._build_packet_sort_sql(sort_key, sort_desc)
        sql = """
            SELECT id, ts, src_ip, dst_ip, src_port, dst_port, proto, length, direction, process_id, process_name, source
            FROM offline_packets
            WHERE 1=1
        """
        args: list = []
        if source:
            sql += " AND source = ?"
            args.append(source)
        if process_name:
            sql += " AND process_name LIKE ?"
            args.append(f"%{process_name}%")
        if ip:
            sql += " AND (src_ip LIKE ? OR dst_ip LIKE ?)"
            args.extend([f"%{ip}%", f"%{ip}%"])
        if extra_sql:
            sql += extra_sql
            if extra_args:
                args.extend(extra_args)
        sql += f" ORDER BY {sort_field}"
        if limit is not None and int(limit) > 0:
            sql += " LIMIT ? OFFSET ?"
            args.extend([int(limit), max(0, int(offset))])
        rows = self.conn.execute(sql, args).fetchall()
        cols = ["id", "ts", "src_ip", "dst_ip", "src_port", "dst_port", "proto", "length", "direction", "process_id", "process_name", "source"]
        out = [dict(zip(cols, row)) for row in rows]
        for row in out:
            row["id"] = self._encode_id(int(row["id"] or 0))
        return out

    def count_packets(
        self,
        process_name: str = "",
        ip: str = "",
        source: str = "offline",
        extra_sql: str = "",
        extra_args: list | None = None,
    ) -> int:
        sql = """
            SELECT COUNT(1)
            FROM offline_packets
            WHERE 1=1
        """
        args: list = []
        if source:
            sql += " AND source = ?"
            args.append(source)
        if process_name:
            sql += " AND process_name LIKE ?"
            args.append(f"%{process_name}%")
        if ip:
            sql += " AND (src_ip LIKE ? OR dst_ip LIKE ?)"
            args.extend([f"%{ip}%", f"%{ip}%"])
        if extra_sql:
            sql += extra_sql
            if extra_args:
                args.extend(extra_args)
        row = self.conn.execute(sql, args).fetchone()
        return int(row[0] if row else 0)

    def query_frames(
        self,
        limit: int | None,
        offset: int = 0,
        source: str = "offline",
        search_text: str = "",
        linktype: int = 0,
    ) -> list[dict]:
        sql = """
            SELECT id, frame_no, ts, linktype, iface, frame_type, caplen, wirelen, summary, raw_hex, source
            FROM offline_frames
            WHERE 1=1
        """
        args: list = []
        if source:
            sql += " AND source = ?"
            args.append(source)
        if int(linktype or 0) > 0:
            sql += " AND linktype = ?"
            args.append(int(linktype))
        if search_text:
            sql += " AND (summary LIKE ? OR raw_hex LIKE ? OR iface LIKE ? OR frame_type LIKE ?)"
            like = f"%{search_text}%"
            args.extend([like, like, like, like])
        sql += " ORDER BY ts ASC, id ASC"
        if limit is not None and int(limit) > 0:
            sql += " LIMIT ? OFFSET ?"
            args.extend([int(limit), max(0, int(offset))])
        rows = self.conn.execute(sql, args).fetchall()
        cols = ["id", "frame_no", "ts", "linktype", "iface", "frame_type", "caplen", "wirelen", "summary", "raw_hex", "source"]
        out = [dict(zip(cols, row)) for row in rows]
        for row in out:
            row["id"] = self._encode_frame_id(int(row["id"] or 0))
        return out

    def count_frames(self, source: str = "offline", search_text: str = "", linktype: int = 0) -> int:
        sql = """
            SELECT COUNT(1)
            FROM offline_frames
            WHERE 1=1
        """
        args: list = []
        if source:
            sql += " AND source = ?"
            args.append(source)
        if int(linktype or 0) > 0:
            sql += " AND linktype = ?"
            args.append(int(linktype))
        if search_text:
            sql += " AND (summary LIKE ? OR raw_hex LIKE ? OR iface LIKE ? OR frame_type LIKE ?)"
            like = f"%{search_text}%"
            args.extend([like, like, like, like])
        row = self.conn.execute(sql, args).fetchone()
        return int(row[0] if row else 0)

    @staticmethod
    def _build_packet_sort_sql(sort_key: str, sort_desc: bool) -> str:
        key = str(sort_key or "").strip().lower()
        direction = "DESC" if sort_desc else "ASC"
        field_map = {
            "ts": "ts",
            "id": "id",
            "process_name": "lower(process_name)",
            "src_ip": "src_ip",
            "dst_ip": "dst_ip",
            "src_port": "src_port",
            "dst_port": "dst_port",
            "proto": "proto",
            "length": "length",
            "source": "source",
        }
        field_sql = field_map.get(key, "ts")
        return f"{field_sql} {direction}, id {direction}"

    def query_packets_by_ids(self, packet_ids: list[int]) -> list[dict]:
        ids: list[int] = []
        for packet_id in packet_ids:
            real_id = self._decode_id(int(packet_id))
            if real_id > 0:
                ids.append(real_id)
        if not ids:
            return []
        placeholders = ",".join(["?"] * len(ids))
        sql = f"""
            SELECT id, ts, src_ip, dst_ip, src_port, dst_port, proto, length, direction, process_id, process_name, source
            FROM offline_packets
            WHERE id IN ({placeholders})
            ORDER BY id DESC
        """  # nosec
        rows = self.conn.execute(sql, ids).fetchall()
        cols = ["id", "ts", "src_ip", "dst_ip", "src_port", "dst_port", "proto", "length", "direction", "process_id", "process_name", "source"]
        out = [dict(zip(cols, row)) for row in rows]
        for row in out:
            row["id"] = self._encode_id(int(row["id"] or 0))
        return out

    def query_packet_detail(self, packet_id: int) -> dict | None:
        real_id = self._decode_id(packet_id)
        if real_id <= 0:
            return None
        row = self.conn.execute(
            """
            SELECT id, ts, src_ip, dst_ip, src_port, dst_port, proto, length, direction, process_id, process_name, raw_hex, source
            FROM offline_packets
            WHERE id = ?
            LIMIT 1
            """,
            [int(real_id)],
        ).fetchone()
        if row is None:
            return None
        cols = ["id", "ts", "src_ip", "dst_ip", "src_port", "dst_port", "proto", "length", "direction", "process_id", "process_name", "raw_hex", "source"]
        out = dict(zip(cols, row))
        out["id"] = self._encode_id(int(out["id"] or 0))
        return out

    def query_packet_details(self, packet_ids: list[int]) -> list[dict]:
        real_ids = [self._decode_id(int(packet_id)) for packet_id in packet_ids]
        real_ids = [real_id for real_id in real_ids if real_id > 0]
        if not real_ids:
            return []
        placeholders = ",".join(["?"] * len(real_ids))
        rows = self.conn.execute(
            f"""
            SELECT id, ts, src_ip, dst_ip, src_port, dst_port, proto, length, direction, process_id, process_name, raw_hex, source
            FROM offline_packets
            WHERE id IN ({placeholders})
            ORDER BY id DESC
            """,  # nosec
            real_ids,
        ).fetchall()
        cols = ["id", "ts", "src_ip", "dst_ip", "src_port", "dst_port", "proto", "length", "direction", "process_id", "process_name", "raw_hex", "source"]
        out = [dict(zip(cols, row)) for row in rows]
        for row in out:
            row["id"] = self._encode_id(int(row["id"] or 0))
        return out

    def query_frame_detail(self, frame_id: int) -> dict | None:
        real_id = self._decode_frame_id(frame_id)
        if real_id <= 0:
            return None
        rows = self.conn.execute(
            """
            SELECT id, frame_no, ts, linktype, iface, frame_type, caplen, wirelen, summary, raw_hex, source
            FROM offline_frames
            WHERE id = ?
            LIMIT 1
            """,
            [int(real_id)],
        ).fetchall()
        if not rows:
            return None
        cols = ["id", "frame_no", "ts", "linktype", "iface", "frame_type", "caplen", "wirelen", "summary", "raw_hex", "source"]
        out = dict(zip(cols, rows[0]))
        out["id"] = self._encode_frame_id(int(out["id"] or 0))
        return out

    def query_frame_details(self, frame_ids: list[int]) -> list[dict]:
        real_ids = [self._decode_frame_id(int(frame_id)) for frame_id in frame_ids]
        real_ids = [real_id for real_id in real_ids if real_id > 0]
        if not real_ids:
            return []
        placeholders = ",".join(["?"] * len(real_ids))
        rows = self.conn.execute(
            f"""
            SELECT id, frame_no, ts, linktype, iface, frame_type, caplen, wirelen, summary, raw_hex, source
            FROM offline_frames
            WHERE id IN ({placeholders})
            ORDER BY id DESC
            """,  # nosec
            real_ids,
        ).fetchall()
        cols = ["id", "frame_no", "ts", "linktype", "iface", "frame_type", "caplen", "wirelen", "summary", "raw_hex", "source"]
        out = [dict(zip(cols, row)) for row in rows]
        for row in out:
            row["id"] = self._encode_frame_id(int(row["id"] or 0))
        return out

    def query_flow_packets(self, packet_id: int, limit: int = 3000) -> list[dict]:
        real_id = self._decode_id(int(packet_id))
        if real_id <= 0:
            return []
        rows = self.conn.execute(
            """
            WITH seed AS (
                SELECT src_ip, dst_ip, src_port, dst_port, proto, source
                FROM offline_packets
                WHERE id = ?
                LIMIT 1
            )
            SELECT p.id, p.ts, p.src_ip, p.dst_ip, p.src_port, p.dst_port, p.proto, p.length, p.process_name, p.raw_hex, p.source
            FROM offline_packets AS p
            INNER JOIN seed AS s
                ON p.source = COALESCE(s.source, 'offline')
               AND p.proto = UPPER(COALESCE(s.proto, ''))
               AND (
                    (p.src_ip = s.src_ip AND p.dst_ip = s.dst_ip AND p.src_port = s.src_port AND p.dst_port = s.dst_port)
                    OR
                    (p.src_ip = s.dst_ip AND p.dst_ip = s.src_ip AND p.src_port = s.dst_port AND p.dst_port = s.src_port)
               )
            ORDER BY ts ASC, id ASC
            LIMIT ?
            """,
            [int(real_id), max(1, int(limit))],
        ).fetchall()
        cols = ["id", "ts", "src_ip", "dst_ip", "src_port", "dst_port", "proto", "length", "process_name", "raw_hex", "source"]
        out = [dict(zip(cols, row)) for row in rows]
        for row in out:
            row["id"] = self._encode_id(int(row["id"] or 0))
        return out

    def close(self) -> None:
        self.conn.close()
