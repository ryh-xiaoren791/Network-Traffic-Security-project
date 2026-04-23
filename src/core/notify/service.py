from __future__ import annotations

import platform
import subprocess
import time


class NotificationService:
    def __init__(self) -> None:
        self._cache: dict[str, float] = {}
        self._toast = None

    def notify_high_risk(self, alert: dict) -> bool:
        if platform.system().lower() != "windows":
            return False
        if str(alert.get("level", "")).lower() != "high":
            return False
        src_ip = str(alert.get("src_ip", ""))
        dst_ip = str(alert.get("dst_ip", ""))
        reason = str(alert.get("reason", ""))
        key = f"{src_ip}|{dst_ip}|{reason[:80]}"
        now = time.time()
        last = self._cache.get(key, 0.0)
        if now - last < 45:
            return False
        self._cache[key] = now
        title = "Network Security Warning"
        msg = f"High-risk behavior: {src_ip} -> {dst_ip}. {reason[:120]}"
        return self._send_notification(title, msg)

    def _send_notification(self, title: str, message: str) -> bool:
        return self._notify_win10toast(title, message) or self._notify_powershell_toast(title, message)

    def _notify_win10toast(self, title: str, message: str) -> bool:
        try:
            if self._toast is None:
                from win10toast import ToastNotifier

                self._toast = ToastNotifier()
            self._toast.show_toast(title, message, duration=8, threaded=True)
            return True
        except Exception:
            return False

    def _notify_powershell_toast(self, title: str, message: str) -> bool:
        safe_title = title.replace("'", " ").replace('"', " ")
        safe_msg = message.replace("'", " ").replace('"', " ")
        script = (
            "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null;"
            "[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] > $null;"
            "$xml = New-Object Windows.Data.Xml.Dom.XmlDocument;"
            "$xml.LoadXml(\"<toast><visual><binding template='ToastGeneric'><text>"
            + safe_title
            + "</text><text>"
            + safe_msg
            + "</text></binding></visual></toast>\");"
            "$toast = [Windows.UI.Notifications.ToastNotification]::new($xml);"
            "$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('AI-Traffic-Guard');"
            "$notifier.Show($toast);"
        )
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True,
            text=True,
            check=False,
        )
        return result.returncode == 0
