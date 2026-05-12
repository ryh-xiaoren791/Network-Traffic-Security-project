import ipaddress
import socket
import threading
import time
from queue import Empty, Queue

from src.core.storage.db import Database, now_text


class ListService:
    def __init__(self, db: Database) -> None:
        self.db = db
        self._dns_cache: dict[str, str] = {}
        self._dns_pending: set[str] = set()
        self._dns_queue: Queue[str] = Queue(maxsize=2048)
        self._dns_cache_limit = 4096
        self._dns_stop_event = threading.Event()
        self._dns_worker = threading.Thread(target=self._dns_resolve_loop, daemon=True)
        self._dns_worker.start()
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
        if not self._should_resolve_ip(ip):
            self._remember_dns(ip, "")
            return ""
        self._schedule_host_resolve(ip)
        return ""

    @staticmethod
    def _should_resolve_ip(ip: str) -> bool:
        try:
            parsed = ipaddress.ip_address(ip)
            if parsed.is_private or parsed.is_loopback or parsed.is_reserved or parsed.is_multicast:
                return False
        except ValueError:
            return False
        return True

    def _schedule_host_resolve(self, ip: str) -> None:
        if ip in self._dns_pending or ip in self._dns_cache:
            return
        self._dns_pending.add(ip)
        try:
            self._dns_queue.put_nowait(ip)
        except Exception:
            self._dns_pending.discard(ip)

    def _remember_dns(self, ip: str, host: str) -> None:
        if ip in self._dns_cache:
            self._dns_cache.pop(ip, None)
        elif len(self._dns_cache) >= self._dns_cache_limit:
            oldest_ip = next(iter(self._dns_cache), None)
            if oldest_ip is not None:
                self._dns_cache.pop(oldest_ip, None)
        self._dns_cache[ip] = host

    def _dns_resolve_loop(self) -> None:
        while not self._dns_stop_event.is_set():
            try:
                ip = self._dns_queue.get(timeout=0.5)
            except Empty:
                continue
            if ip == "__stop__":
                self._dns_pending.discard(ip)
                self._dns_queue.task_done()
                break
            host = ""
            try:
                host, _, _ = socket.gethostbyaddr(ip)
            except Exception:
                host = ""
            self._remember_dns(ip, host)
            self._dns_pending.discard(ip)
            self._dns_queue.task_done()
            time.sleep(0.01)

    def close(self) -> None:
        self._dns_stop_event.set()
        try:
            self._dns_queue.put_nowait("__stop__")
        except Exception:
            pass
        if self._dns_worker.is_alive():
            self._dns_worker.join(timeout=1.0)
        self._dns_pending.clear()
