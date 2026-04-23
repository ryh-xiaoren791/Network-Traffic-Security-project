import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

from src.config import CONFIG


def now_text() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class Database:
    def __init__(self, db_path: Path | None = None) -> None:
        self.db_path = db_path or CONFIG.db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()
        self._init_default_users()

    def _init_schema(self) -> None:
        c = self.conn.cursor()
        c.execute("PRAGMA journal_mode=WAL;")
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL DEFAULT '',
                role TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1
            )
            """
        )
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS blacklist_whitelist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                list_type TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                remark TEXT DEFAULT '',
                updated_at TEXT NOT NULL
            )
            """
        )
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER DEFAULT 0,
                dst_port INTEGER DEFAULT 0,
                proto TEXT DEFAULT '',
                process_name TEXT DEFAULT '',
                process_id INTEGER DEFAULT 0,
                category TEXT,
                sub_category TEXT,
                level TEXT,
                attack_type TEXT DEFAULT '',
                attack_desc TEXT DEFAULT '',
                mitigation TEXT DEFAULT '',
                reason TEXT,
                score REAL,
                handled INTEGER NOT NULL DEFAULT 0,
                source TEXT DEFAULT 'live'
            )
            """
        )
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                username TEXT,
                action TEXT,
                target TEXT,
                detail TEXT
            )
            """
        )
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS traffic_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                inbound_packets INTEGER,
                outbound_packets INTEGER,
                active_sessions INTEGER
            )
            """
        )
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS captured_packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                proto TEXT,
                length INTEGER,
                direction TEXT,
                process_id INTEGER DEFAULT 0,
                process_name TEXT DEFAULT '',
                raw_hex TEXT DEFAULT '',
                source TEXT DEFAULT 'live'
            )
            """
        )
        self._ensure_column("users", "password", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("alerts", "process_name", "TEXT DEFAULT ''")
        self._ensure_column("alerts", "process_id", "INTEGER DEFAULT 0")
        self._ensure_column("alerts", "attack_type", "TEXT DEFAULT ''")
        self._ensure_column("alerts", "attack_desc", "TEXT DEFAULT ''")
        self._ensure_column("alerts", "mitigation", "TEXT DEFAULT ''")
        self._ensure_column("alerts", "src_port", "INTEGER DEFAULT 0")
        self._ensure_column("alerts", "dst_port", "INTEGER DEFAULT 0")
        self._ensure_column("alerts", "proto", "TEXT DEFAULT ''")
        self._ensure_column("alerts", "source", "TEXT DEFAULT 'live'")
        self._ensure_indexes()
        self.conn.commit()

    def _ensure_column(self, table: str, column: str, ddl: str) -> None:
        c = self.conn.cursor()
        c.execute(f"PRAGMA table_info({table})")
        cols = {r["name"] for r in c.fetchall()}
        if column in cols:
            return
        c.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")

    def _ensure_indexes(self) -> None:
        c = self.conn.cursor()
        # 离线实战查询高频条件加索引，避免按IP/端口/协议过滤时全表扫描。
        c.execute("CREATE INDEX IF NOT EXISTS idx_packets_source_id ON captured_packets(source, id DESC)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_packets_src_ip ON captured_packets(src_ip)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_packets_dst_ip ON captured_packets(dst_ip)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_packets_proto ON captured_packets(proto)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_packets_src_port ON captured_packets(src_port)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_packets_dst_port ON captured_packets(dst_port)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_packets_process_name ON captured_packets(process_name)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_alerts_source_id ON alerts(source, id DESC)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_alerts_src_dst ON alerts(src_ip, dst_ip)")

    def suspend_offline_import_indexes(self) -> None:
        c = self.conn.cursor()
        c.execute("DROP INDEX IF EXISTS idx_packets_source_id")
        c.execute("DROP INDEX IF EXISTS idx_packets_src_ip")
        c.execute("DROP INDEX IF EXISTS idx_packets_dst_ip")
        c.execute("DROP INDEX IF EXISTS idx_packets_proto")
        c.execute("DROP INDEX IF EXISTS idx_packets_src_port")
        c.execute("DROP INDEX IF EXISTS idx_packets_dst_port")
        c.execute("DROP INDEX IF EXISTS idx_packets_process_name")
        c.execute("DROP INDEX IF EXISTS idx_alerts_source_id")
        c.execute("DROP INDEX IF EXISTS idx_alerts_src_dst")
        self.conn.commit()

    def resume_offline_import_indexes(self, lightweight: bool = False) -> None:
        if lightweight:
            c = self.conn.cursor()
            c.execute("CREATE INDEX IF NOT EXISTS idx_packets_source_id ON captured_packets(source, id DESC)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_alerts_source_id ON alerts(source, id DESC)")
            self.conn.commit()
            return
        self._ensure_indexes()
        self.conn.commit()

    def _upsert_local_user(self, username: str, password: str, role: str) -> None:
        c = self.conn.cursor()
        c.execute("SELECT id FROM users WHERE username=?", (username,))
        row = c.fetchone()
        if row:
            c.execute(
                "UPDATE users SET password=?, role=?, enabled=1 WHERE username=?",
                (password, role, username),
            )
            self.conn.commit()
            return
        c.execute(
            "INSERT INTO users(username, password, role, enabled) VALUES(?,?,?,1)",
            (username, password, role),
        )
        self.conn.commit()

    def _init_default_users(self) -> None:
        self._upsert_local_user(CONFIG.default_admin_username, CONFIG.default_admin_password, "admin")
        self._upsert_local_user(CONFIG.default_guest_username, CONFIG.default_guest_password, "guest")
        c = self.conn.cursor()
        c.execute(
            "DELETE FROM users WHERE username NOT IN (?, ?)",
            (CONFIG.default_admin_username, CONFIG.default_guest_username),
        )
        self.conn.commit()

    def cleanup_old_logs(self) -> None:
        threshold = (datetime.now() - timedelta(days=CONFIG.sqlite_retention_days)).strftime("%Y-%m-%d %H:%M:%S")
        c = self.conn.cursor()
        c.execute("DELETE FROM alerts WHERE ts < ?", (threshold,))
        c.execute("DELETE FROM audit_logs WHERE ts < ?", (threshold,))
        c.execute("DELETE FROM traffic_stats WHERE ts < ?", (threshold,))
        c.execute("DELETE FROM captured_packets WHERE ts < ?", (threshold,))
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()
