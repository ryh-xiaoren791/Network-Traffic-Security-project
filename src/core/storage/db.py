import hashlib
import hmac
import secrets
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

from src.config import CONFIG


def now_text() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


PASSWORD_HASH_ITERATIONS = 120_000


def hash_password(password: str, salt: str | None = None) -> str:
    raw_password = str(password or "")
    used_salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        raw_password.encode("utf-8"),
        used_salt.encode("utf-8"),
        PASSWORD_HASH_ITERATIONS,
    ).hex()
    return f"pbkdf2_sha256${PASSWORD_HASH_ITERATIONS}${used_salt}${digest}"


def is_password_hash(value: str) -> bool:
    return str(value or "").startswith("pbkdf2_sha256$")


def verify_password(password: str, stored_value: str) -> bool:
    stored = str(stored_value or "")
    if not is_password_hash(stored):
        return hmac.compare_digest(str(password or ""), stored)
    try:
        algorithm, iterations_text, salt, expected = stored.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        iterations = int(iterations_text)
    except Exception:
        return False
    actual = hashlib.pbkdf2_hmac(
        "sha256",
        str(password or "").encode("utf-8"),
        salt.encode("utf-8"),
        iterations,
    ).hex()
    return hmac.compare_digest(actual, expected)


class Database:
    def __init__(self, db_path: Path | None = None) -> None:
        self.db_path = db_path or CONFIG.db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()
        self._init_default_users()
        self._bootstrap_flow_risk_summary()

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
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS flow_risk_summary (
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                src_port INTEGER NOT NULL DEFAULT 0,
                dst_port INTEGER NOT NULL DEFAULT 0,
                proto TEXT NOT NULL DEFAULT '',
                source TEXT NOT NULL DEFAULT 'live',
                max_level_rank INTEGER NOT NULL DEFAULT 0,
                last_alert_ts TEXT NOT NULL DEFAULT '',
                alert_count INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (src_ip, dst_ip, src_port, dst_port, proto, source)
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
        c.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_flow_risk_source_level
            ON flow_risk_summary(source, max_level_rank DESC, last_alert_ts DESC)
            """
        )

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
        c.execute("DROP INDEX IF EXISTS idx_flow_risk_source_level")
        self.conn.commit()

    def resume_offline_import_indexes(self, lightweight: bool = False) -> None:
        if lightweight:
            c = self.conn.cursor()
            c.execute("CREATE INDEX IF NOT EXISTS idx_packets_source_id ON captured_packets(source, id DESC)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_alerts_source_id ON alerts(source, id DESC)")
            c.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_flow_risk_source_level
                ON flow_risk_summary(source, max_level_rank DESC, last_alert_ts DESC)
                """
            )
            self.conn.commit()
            return
        self._ensure_indexes()
        self.conn.commit()

    @staticmethod
    def level_rank(level: str) -> int:
        text = str(level or "").strip().lower()
        if text == "high":
            return 3
        if text == "medium":
            return 2
        if text == "low":
            return 1
        return 0

    def upsert_flow_risk_summary(self, alerts: list[dict], commit: bool = True) -> None:
        if not alerts:
            return
        rows: list[tuple] = []
        for alert in alerts:
            src_ip = str(alert.get("src_ip", "") or "")
            dst_ip = str(alert.get("dst_ip", "") or "")
            src_port = int(alert.get("src_port", 0) or 0)
            dst_port = int(alert.get("dst_port", 0) or 0)
            proto = str(alert.get("proto", "") or "").upper()
            source = str(alert.get("source", "live") or "live")
            ts = str(alert.get("ts", "") or "")
            level_rank = self.level_rank(str(alert.get("level", "") or ""))
            if not (src_ip or dst_ip or proto):
                continue
            rows.append((src_ip, dst_ip, src_port, dst_port, proto, source, level_rank, ts, 1))
            rows.append((dst_ip, src_ip, dst_port, src_port, proto, source, level_rank, ts, 1))
        if not rows:
            return
        c = self.conn.cursor()
        c.executemany(
            """
            INSERT INTO flow_risk_summary(
                src_ip, dst_ip, src_port, dst_port, proto, source, max_level_rank, last_alert_ts, alert_count
            )
            VALUES(?,?,?,?,?,?,?,?,?)
            ON CONFLICT(src_ip, dst_ip, src_port, dst_port, proto, source)
            DO UPDATE SET
                max_level_rank = MAX(flow_risk_summary.max_level_rank, excluded.max_level_rank),
                last_alert_ts = CASE
                    WHEN excluded.last_alert_ts >= flow_risk_summary.last_alert_ts THEN excluded.last_alert_ts
                    ELSE flow_risk_summary.last_alert_ts
                END,
                alert_count = flow_risk_summary.alert_count + excluded.alert_count
            """,
            rows,
        )
        if commit:
            self.conn.commit()

    def rebuild_flow_risk_summary(self, source: str = "", commit: bool = True) -> None:
        c = self.conn.cursor()
        src = str(source or "").strip()
        if src:
            c.execute("DELETE FROM flow_risk_summary WHERE source=?", (src,))
            c.execute(
                """
                INSERT INTO flow_risk_summary(
                    src_ip, dst_ip, src_port, dst_port, proto, source, max_level_rank, last_alert_ts, alert_count
                )
                SELECT
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    UPPER(COALESCE(proto, '')),
                    source,
                    MAX(
                        CASE LOWER(COALESCE(level, ''))
                            WHEN 'high' THEN 3
                            WHEN 'medium' THEN 2
                            WHEN 'low' THEN 1
                            ELSE 0
                        END
                    ),
                    MAX(ts),
                    COUNT(1)
                FROM alerts
                WHERE source=?
                GROUP BY src_ip, dst_ip, src_port, dst_port, UPPER(COALESCE(proto, '')), source
                ON CONFLICT(src_ip, dst_ip, src_port, dst_port, proto, source)
                DO UPDATE SET
                    max_level_rank = MAX(flow_risk_summary.max_level_rank, excluded.max_level_rank),
                    last_alert_ts = CASE
                        WHEN excluded.last_alert_ts >= flow_risk_summary.last_alert_ts THEN excluded.last_alert_ts
                        ELSE flow_risk_summary.last_alert_ts
                    END,
                    alert_count = flow_risk_summary.alert_count + excluded.alert_count
                """,
                (src,),
            )
            c.execute(
                """
                INSERT INTO flow_risk_summary(
                    src_ip, dst_ip, src_port, dst_port, proto, source, max_level_rank, last_alert_ts, alert_count
                )
                SELECT
                    dst_ip,
                    src_ip,
                    dst_port,
                    src_port,
                    UPPER(COALESCE(proto, '')),
                    source,
                    MAX(
                        CASE LOWER(COALESCE(level, ''))
                            WHEN 'high' THEN 3
                            WHEN 'medium' THEN 2
                            WHEN 'low' THEN 1
                            ELSE 0
                        END
                    ),
                    MAX(ts),
                    COUNT(1)
                FROM alerts
                WHERE source=?
                GROUP BY dst_ip, src_ip, dst_port, src_port, UPPER(COALESCE(proto, '')), source
                ON CONFLICT(src_ip, dst_ip, src_port, dst_port, proto, source)
                DO UPDATE SET
                    max_level_rank = MAX(flow_risk_summary.max_level_rank, excluded.max_level_rank),
                    last_alert_ts = CASE
                        WHEN excluded.last_alert_ts >= flow_risk_summary.last_alert_ts THEN excluded.last_alert_ts
                        ELSE flow_risk_summary.last_alert_ts
                    END,
                    alert_count = flow_risk_summary.alert_count + excluded.alert_count
                """,
                (src,),
            )
        else:
            c.execute("DELETE FROM flow_risk_summary")
            c.execute(
                """
                INSERT INTO flow_risk_summary(
                    src_ip, dst_ip, src_port, dst_port, proto, source, max_level_rank, last_alert_ts, alert_count
                )
                SELECT
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    UPPER(COALESCE(proto, '')),
                    source,
                    MAX(
                        CASE LOWER(COALESCE(level, ''))
                            WHEN 'high' THEN 3
                            WHEN 'medium' THEN 2
                            WHEN 'low' THEN 1
                            ELSE 0
                        END
                    ),
                    MAX(ts),
                    COUNT(1)
                FROM alerts
                GROUP BY src_ip, dst_ip, src_port, dst_port, UPPER(COALESCE(proto, '')), source
                ON CONFLICT(src_ip, dst_ip, src_port, dst_port, proto, source)
                DO UPDATE SET
                    max_level_rank = MAX(flow_risk_summary.max_level_rank, excluded.max_level_rank),
                    last_alert_ts = CASE
                        WHEN excluded.last_alert_ts >= flow_risk_summary.last_alert_ts THEN excluded.last_alert_ts
                        ELSE flow_risk_summary.last_alert_ts
                    END,
                    alert_count = flow_risk_summary.alert_count + excluded.alert_count
                """
            )
            c.execute(
                """
                INSERT INTO flow_risk_summary(
                    src_ip, dst_ip, src_port, dst_port, proto, source, max_level_rank, last_alert_ts, alert_count
                )
                SELECT
                    dst_ip,
                    src_ip,
                    dst_port,
                    src_port,
                    UPPER(COALESCE(proto, '')),
                    source,
                    MAX(
                        CASE LOWER(COALESCE(level, ''))
                            WHEN 'high' THEN 3
                            WHEN 'medium' THEN 2
                            WHEN 'low' THEN 1
                            ELSE 0
                        END
                    ),
                    MAX(ts),
                    COUNT(1)
                FROM alerts
                GROUP BY dst_ip, src_ip, dst_port, src_port, UPPER(COALESCE(proto, '')), source
                ON CONFLICT(src_ip, dst_ip, src_port, dst_port, proto, source)
                DO UPDATE SET
                    max_level_rank = MAX(flow_risk_summary.max_level_rank, excluded.max_level_rank),
                    last_alert_ts = CASE
                        WHEN excluded.last_alert_ts >= flow_risk_summary.last_alert_ts THEN excluded.last_alert_ts
                        ELSE flow_risk_summary.last_alert_ts
                    END,
                    alert_count = flow_risk_summary.alert_count + excluded.alert_count
                """
            )
        if commit:
            self.conn.commit()

    def _upsert_local_user(self, username: str, password: str, role: str) -> None:
        c = self.conn.cursor()
        c.execute("SELECT id, password, role FROM users WHERE username=?", (username,))
        row = c.fetchone()
        if row:
            updates: list[str] = []
            args: list[object] = []
            if str(row["role"] or "") != role:
                updates.append("role=?")
                args.append(role)
            stored_password = str(row["password"] or "")
            if not stored_password:
                updates.append("password=?")
                args.append(hash_password(password))
            if updates:
                args.append(username)
                c.execute(f"UPDATE users SET {', '.join(updates)} WHERE username=?", tuple(args))  # nosec
                self.conn.commit()
            return
        c.execute(
            "INSERT INTO users(username, password, role, enabled) VALUES(?,?,?,1)",
            (username, hash_password(password), role),
        )
        self.conn.commit()

    def _init_default_users(self) -> None:
        self._upsert_local_user(CONFIG.default_admin_username, CONFIG.default_admin_password, "admin")
        self._upsert_local_user(CONFIG.default_guest_username, CONFIG.default_guest_password, "guest")

    def _bootstrap_flow_risk_summary(self) -> None:
        c = self.conn.cursor()
        c.execute("SELECT COUNT(1) FROM flow_risk_summary")
        summary_count = int(c.fetchone()[0] or 0)
        if summary_count > 0:
            return
        c.execute("SELECT COUNT(1) FROM alerts")
        alert_count = int(c.fetchone()[0] or 0)
        if alert_count <= 0:
            return
        self.rebuild_flow_risk_summary(commit=True)

    def cleanup_old_logs(self) -> None:
        threshold = (datetime.now() - timedelta(days=CONFIG.sqlite_retention_days)).strftime("%Y-%m-%d %H:%M:%S")
        c = self.conn.cursor()
        c.execute("DELETE FROM alerts WHERE ts < ?", (threshold,))
        deleted_alerts = int(c.rowcount or 0)
        c.execute("DELETE FROM audit_logs WHERE ts < ?", (threshold,))
        c.execute("DELETE FROM traffic_stats WHERE ts < ?", (threshold,))
        c.execute("DELETE FROM captured_packets WHERE ts < ?", (threshold,))
        self.conn.commit()
        if deleted_alerts > 0:
            self.rebuild_flow_risk_summary(commit=True)

    def close(self) -> None:
        self.conn.close()
