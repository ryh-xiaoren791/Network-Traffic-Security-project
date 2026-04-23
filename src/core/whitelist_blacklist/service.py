import ipaddress
import socket

from src.core.storage.db import Database, now_text


class ListService:
    def __init__(self, db: Database) -> None:
        self.db = db
        self._dns_cache: dict[str, str] = {}
        self.privacy_tracker_keywords = (
            "doubleclick",
            "google-analytics",
            "googletagmanager",
            "facebook",
            "appsflyer",
            "branch",
            "mixpanel",
            "amplitude",
            "segment",
            "adservice",
            "analytics",
            "tracking",
            "telemetry",
        )

    def all_items(self) -> list[dict]:
        c = self.db.conn.cursor()
        c.execute("SELECT * FROM blacklist_whitelist ORDER BY id DESC")
        return [dict(row) for row in c.fetchall()]

    def upsert(self, ip: str, list_type: str, enabled: int, remark: str) -> None:
        c = self.db.conn.cursor()
        c.execute(
            "INSERT INTO blacklist_whitelist(ip, list_type, enabled, remark, updated_at) VALUES(?,?,?,?,?)",
            (ip, list_type, enabled, remark, now_text()),
        )
        self.db.conn.commit()

    def update_item(self, item_id: int, enabled: int, remark: str) -> None:
        c = self.db.conn.cursor()
        c.execute(
            "UPDATE blacklist_whitelist SET enabled=?, remark=?, updated_at=? WHERE id=?",
            (enabled, remark, now_text(), item_id),
        )
        self.db.conn.commit()

    def delete(self, item_id: int) -> None:
        c = self.db.conn.cursor()
        c.execute("DELETE FROM blacklist_whitelist WHERE id=?", (item_id,))
        self.db.conn.commit()

    def classify_ip(self, ip: str) -> str | None:
        c = self.db.conn.cursor()
        c.execute("SELECT list_type FROM blacklist_whitelist WHERE ip=? AND enabled=1", (ip,))
        rows = c.fetchall()
        types = {r["list_type"] for r in rows}
        if "white" in types:
            return "white"
        if "black" in types:
            return "black"
        return None

    def classify_target(self, ip: str, enable_tracker_lookup: bool = True) -> dict:
        list_type = self.classify_ip(ip)
        if list_type == "white":
            return {"list_type": "white", "source": "manual_whitelist", "remark": ""}
        if list_type == "black":
            return {"list_type": "black", "source": "manual_blacklist", "remark": "命中黑名单"}
        if not enable_tracker_lookup:
            return {"list_type": None, "source": "", "remark": ""}
        tracker_host = self._match_tracker_host(ip)
        if tracker_host:
            return {"list_type": "black", "source": "privacy_tracker", "remark": f"命中隐私追踪域名: {tracker_host}"}
        return {"list_type": None, "source": "", "remark": ""}

    def _match_tracker_host(self, ip: str) -> str:
        host = self._resolve_host(ip)
        if not host:
            return ""
        low = host.lower()
        for kw in self.privacy_tracker_keywords:
            if kw in low:
                return host
        return ""

    def _resolve_host(self, ip: str) -> str:
        if ip in self._dns_cache:
            return self._dns_cache[ip]
        try:
            parsed = ipaddress.ip_address(ip)
            if parsed.is_private or parsed.is_loopback or parsed.is_reserved or parsed.is_multicast:
                self._dns_cache[ip] = ""
                return ""
        except ValueError:
            self._dns_cache[ip] = ""
            return ""
        try:
            host, _, _ = socket.gethostbyaddr(ip)
        except Exception:
            host = ""
        self._dns_cache[ip] = host
        return host
