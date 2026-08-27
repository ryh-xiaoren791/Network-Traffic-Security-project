from __future__ import annotations

from dataclasses import dataclass
import platform
import subprocess
import time
from xml.sax.saxutils import escape as escape_xml


WINDOWS_TOAST_APP_ID = r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe"


@dataclass(frozen=True)
class NotificationPayload:
    title: str
    message: str
    cache_key: str


class NotificationService:
    DEDUPE_SECONDS = 45
    TITLE_MAX_LEN = 64
    MESSAGE_MAX_LEN = 220
    POWERSHELL_BASE_ARGS = [
        "powershell",
        "-NoProfile",
        "-WindowStyle",
        "Hidden",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
    ]

    def __init__(self) -> None:
        self._cache: dict[str, float] = {}

    def notify_high_risk(self, alert: dict) -> bool:
        if not self._supports_windows_notifications():
            return False
        payload = self._build_high_risk_payload(alert)
        if payload is None or self._is_duplicate(payload.cache_key):
            return False
        self._cache[payload.cache_key] = time.time()
        return self._send_notification(payload.title, payload.message)

    def _send_notification(self, title: str, message: str) -> bool:
        for sender in (
            self._notify_native_toast,
            self._notify_powershell_balloon,
        ):
            if sender(title, message):
                return True
        return False

    def _notify_native_toast(self, title: str, message: str) -> bool:
        script = self._build_native_toast_script(title, message)
        return self._run_hidden_powershell(script)

    def _build_high_risk_payload(self, alert: dict) -> NotificationPayload | None:
        if str(alert.get("level", "")).lower() != "high":
            return None
        src_endpoint = self._format_endpoint(alert.get("src_ip", ""), alert.get("src_port", ""))
        dst_endpoint = self._format_endpoint(alert.get("dst_ip", ""), alert.get("dst_port", ""))
        proto = self._normalize_short_text(alert.get("proto", ""), fallback="IP")
        sub_category = self._normalize_short_text(alert.get("sub_category", ""), fallback="Suspicious activity")
        reason = self._normalize_short_text(alert.get("reason", ""), fallback="High-risk behavior detected")
        process_name = self._normalize_short_text(alert.get("process_name", ""))
        process_segment = f" | Process: {process_name}" if process_name else ""
        title = f"High-Risk Alert: {sub_category}"
        message = f"{proto} {src_endpoint} -> {dst_endpoint}{process_segment} | {reason}"
        cache_key = self._build_cache_key(alert, sub_category, reason)
        return NotificationPayload(title=title, message=message, cache_key=cache_key)

    def _build_cache_key(self, alert: dict, sub_category: str, reason: str) -> str:
        parts = (
            self._normalize_short_text(alert.get("src_ip", ""), fallback="-"),
            self._normalize_short_text(alert.get("dst_ip", ""), fallback="-"),
            self._normalize_short_text(alert.get("dst_port", ""), fallback="-"),
            self._normalize_short_text(alert.get("proto", ""), fallback="-"),
            sub_category,
            reason[:80],
        )
        return "|".join(parts)

    def _build_native_toast_script(self, title: str, message: str) -> str:
        safe_title = escape_xml(self._clip_text(title, self.TITLE_MAX_LEN))
        safe_msg = escape_xml(self._clip_text(message, self.MESSAGE_MAX_LEN))
        xml_payload = (
            '<toast activationType="foreground" duration="long">'
            '<visual><binding template="ToastGeneric">'
            f"<text>{safe_title}</text>"
            f"<text>{safe_msg}</text>"
            "</binding></visual></toast>"
        )
        xml_payload = self._escape_powershell_text(xml_payload)
        app_id = self._escape_powershell_text(WINDOWS_TOAST_APP_ID)
        return (
            "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null; "
            "[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] > $null; "
            f"$xml = '{xml_payload}'; "
            "$doc = New-Object Windows.Data.Xml.Dom.XmlDocument; "
            "$doc.LoadXml($xml); "
            "$toast = [Windows.UI.Notifications.ToastNotification]::new($doc); "
            "$toast.Tag = 'netscope-high-risk'; "
            "$toast.Group = 'netscope-alerts'; "
            f"$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('{app_id}'); "
            "$notifier.Show($toast);"
        )

    def _notify_powershell_balloon(self, title: str, message: str) -> bool:
        safe_title = self._escape_powershell_text(self._clip_text(title, self.TITLE_MAX_LEN))
        safe_msg = self._escape_powershell_text(self._clip_text(message, self.MESSAGE_MAX_LEN))
        script = (
            "Add-Type -AssemblyName System.Windows.Forms; "
            "Add-Type -AssemblyName System.Drawing; "
            "$notify = New-Object System.Windows.Forms.NotifyIcon; "
            "$notify.Icon = [System.Drawing.SystemIcons]::Warning; "
            "$notify.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Warning; "
            "$notify.BalloonTipTitle = '"
            + safe_title
            + "'; "
            "$notify.BalloonTipText = '"
            + safe_msg
            + "'; "
            "$notify.Visible = $true; "
            "$notify.ShowBalloonTip(8000); "
            "Start-Sleep -Milliseconds 9000; "
            "$notify.Dispose();"
        )
        return self._launch_hidden_powershell(script)

    @staticmethod
    def _escape_powershell_text(value: str) -> str:
        return str(value).replace("'", "''").replace("\r", " ").replace("\n", " ")

    @staticmethod
    def _clip_text(value: str, max_len: int) -> str:
        text = str(value).strip()
        return text[:max_len]

    @staticmethod
    def _normalize_short_text(value: object, fallback: str = "") -> str:
        text = str(value or "").strip()
        return text if text else fallback

    def _format_endpoint(self, ip: object, port: object) -> str:
        ip_text = self._normalize_short_text(ip, fallback="unknown")
        port_text = self._normalize_short_text(port)
        if port_text in {"", "0"}:
            return ip_text
        return f"{ip_text}:{port_text}"

    @staticmethod
    def _supports_windows_notifications() -> bool:
        return platform.system().lower() == "windows"

    def _is_duplicate(self, cache_key: str) -> bool:
        now = time.time()
        last = self._cache.get(cache_key, 0.0)
        return now - last < self.DEDUPE_SECONDS

    def _run_hidden_powershell(self, script: str) -> bool:
        try:
            result = subprocess.run(
                self._build_hidden_powershell_command(script),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                startupinfo=self._build_startupinfo(),
                creationflags=self._build_creationflags(),
                check=False,
                timeout=10,
            )
            return result.returncode == 0
        except Exception:
            return False

    def _launch_hidden_powershell(self, script: str) -> bool:
        try:
            subprocess.Popen(
                self._build_hidden_powershell_command(script),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                startupinfo=self._build_startupinfo(),
                creationflags=self._build_creationflags(),
            )
            return True
        except Exception:
            return False

    @classmethod
    def _build_hidden_powershell_command(cls, script: str) -> list[str]:
        return [*cls.POWERSHELL_BASE_ARGS, script]

    @staticmethod
    def _build_startupinfo():
        if hasattr(subprocess, "STARTUPINFO") and hasattr(subprocess, "STARTF_USESHOWWINDOW"):
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = getattr(subprocess, "SW_HIDE", 0)
            return startupinfo
        return None

    @staticmethod
    def _build_creationflags() -> int:
        return int(getattr(subprocess, "CREATE_NO_WINDOW", 0))
