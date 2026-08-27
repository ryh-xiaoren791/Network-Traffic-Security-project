from __future__ import annotations

import unittest
from unittest.mock import patch

from src.core.notify.service import NotificationPayload, NotificationService


class NotificationServiceTests(unittest.TestCase):
    def test_notify_high_risk_uses_dedupe_window(self) -> None:
        service = NotificationService()
        alert = {
            "level": "high",
            "src_ip": "1.1.1.1",
            "dst_ip": "2.2.2.2",
            "dst_port": 443,
            "proto": "TCP",
            "sub_category": "Port scan",
            "reason": "scan detected",
        }

        with patch("src.core.notify.service.platform.system", return_value="Windows"):
            with patch.object(service, "_send_notification", return_value=True) as send_mock:
                self.assertTrue(service.notify_high_risk(alert))
                self.assertFalse(service.notify_high_risk(alert))

        self.assertEqual(send_mock.call_count, 1)

    def test_notify_high_risk_skips_non_high_level(self) -> None:
        service = NotificationService()
        alert = {"level": "medium", "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "reason": "scan detected"}

        with patch("src.core.notify.service.platform.system", return_value="Windows"):
            with patch.object(service, "_send_notification", return_value=True) as send_mock:
                self.assertFalse(service.notify_high_risk(alert))

        send_mock.assert_not_called()

    def test_build_high_risk_payload_contains_contextual_message(self) -> None:
        service = NotificationService()
        alert = {
            "level": "high",
            "src_ip": "10.0.0.8",
            "src_port": 51514,
            "dst_ip": "10.0.0.10",
            "dst_port": 3389,
            "proto": "TCP",
            "sub_category": "RDP brute force",
            "reason": "Multiple failed login attempts",
            "process_name": "mstsc.exe",
        }

        payload = service._build_high_risk_payload(alert)

        self.assertIsInstance(payload, NotificationPayload)
        self.assertIn("RDP brute force", payload.title)
        self.assertIn("10.0.0.8:51514 -> 10.0.0.10:3389", payload.message)
        self.assertIn("Process: mstsc.exe", payload.message)
        self.assertIn("Multiple failed login attempts", payload.message)

    def test_build_cache_key_uses_sub_category_and_target_context(self) -> None:
        service = NotificationService()
        alert = {
            "src_ip": "10.0.0.8",
            "dst_ip": "10.0.0.10",
            "dst_port": 3389,
            "proto": "TCP",
        }

        cache_key = service._build_cache_key(alert, "RDP brute force", "Multiple failed login attempts")

        self.assertEqual(
            cache_key,
            "10.0.0.8|10.0.0.10|3389|TCP|RDP brute force|Multiple failed login attempts",
        )

    def test_send_notification_falls_back_when_native_fails(self) -> None:
        service = NotificationService()

        with patch.object(service, "_notify_native_toast", return_value=False) as native_mock:
            with patch.object(service, "_notify_powershell_balloon", return_value=True) as balloon_mock:
                self.assertTrue(service._send_notification("title", "message"))

        native_mock.assert_called_once_with("title", "message")
        balloon_mock.assert_called_once_with("title", "message")

    def test_build_hidden_powershell_command_contains_hidden_flags(self) -> None:
        command = NotificationService._build_hidden_powershell_command("Write-Host 'ok'")

        self.assertEqual(command[:6], ["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass"])
        self.assertEqual(command[6], "-Command")
        self.assertEqual(command[7], "Write-Host 'ok'")

    def test_build_native_toast_script_contains_expected_metadata(self) -> None:
        service = NotificationService()

        script = service._build_native_toast_script("Alert", "High-risk behavior")

        self.assertIn("CreateToastNotifier", script)
        self.assertIn("netscope-high-risk", script)
        self.assertIn("netscope-alerts", script)
        self.assertIn("ToastGeneric", script)


if __name__ == "__main__":
    unittest.main()
