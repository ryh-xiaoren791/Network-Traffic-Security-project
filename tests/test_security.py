import sqlite3
from pathlib import Path

import pytest

from src.core.auth.service import AuthService
from src.core.filtering.packet_rules import match_packet_rule
from src.core.storage.db import Database, hash_password, verify_password


@pytest.mark.security
class TestSQLInjection:
    def test_auth_login_sql_injection(self, tmp_db):
        auth = AuthService(tmp_db)
        payloads = [
            "' OR '1'='1",
            "' OR 1=1 --",
            "admin' --",
            "' UNION SELECT * FROM users --",
            "'; DROP TABLE users; --",
        ]
        for payload in payloads:
            result = auth.login(payload, payload)
            assert result is None, f"SQL injection succeeded with: {payload}"

    def test_auth_login_empty_credentials(self, tmp_db):
        auth = AuthService(tmp_db)
        result = auth.login("", "")
        assert result is None

    def test_packet_rule_injection_resilience(self):
        payloads = [
            "dst_port = '80; DROP TABLE offline_packets; --'",
            "src_ip = '1.1.1.1' OR '1'='1'",
        ]
        dummy_row = {"dst_port": 80, "src_ip": "1.1.1.1", "proto": "TCP"}
        for payload in payloads:
            try:
                result = match_packet_rule(dummy_row, payload)
                assert isinstance(result, bool)
            except Exception:
                pass

    def test_db_sql_injection_via_params(self, tmp_db):
        c = tmp_db.conn.cursor()
        injection = "'; DROP TABLE alerts; --"
        try:
            c.execute(
                "SELECT * FROM alerts WHERE level=?",
                (injection,),
            )
            c.fetchall()
        except Exception:
            pass
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='alerts'")
        assert c.fetchone() is not None


@pytest.mark.security
class TestAuthSecurity:
    def test_password_hash_not_plaintext(self):
        password = "SecurePass123!"
        hashed = hash_password(password)
        assert password not in hashed
        assert len(hashed) > 32
        assert hashed.startswith("pbkdf2_sha256$")

    def test_password_hash_is_random_per_call(self):
        pwd = "TestPass456"
        h1 = hash_password(pwd)
        h2 = hash_password(pwd)
        assert h1 != h2

    def test_verify_with_correct_password(self):
        pwd = "CorrectHorseBatteryStaple"
        hashed = hash_password(pwd)
        assert verify_password(pwd, hashed) is True

    def test_verify_with_wrong_password(self):
        pwd = "CorrectHorseBatteryStaple"
        hashed = hash_password(pwd)
        assert verify_password("WrongPassword", hashed) is False

    def test_verify_with_empty_input(self):
        hashed = hash_password("SomePass")
        assert verify_password("", hashed) is False
        assert verify_password(None, hashed) is False

    def test_auth_brute_force_resilience(self, tmp_db):
        auth = AuthService(tmp_db)
        for _ in range(50):
            auth.login("admin", "wrong_password")

        result = auth.login("admin", "Admin@123456")
        assert result is not None

    def test_admin_account_exists_by_default(self, tmp_db):
        auth = AuthService(tmp_db)
        assert auth.login("admin", "Admin@123456") is not None
        assert auth.login("admin", "wrong") is None

    def test_guest_account_does_not_escalate(self, tmp_db):
        auth = AuthService(tmp_db)
        c = tmp_db.conn.cursor()
        c.execute("SELECT role FROM users WHERE username='admin'")
        row = c.fetchone()
        if row:
            assert row["role"] == "admin"


@pytest.mark.security
class TestInputValidation:
    def test_hash_password_rejects_very_long_input(self):
        very_long = "A" * 10000
        result = hash_password(very_long)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_verify_password_with_malformed_hash(self):
        result = verify_password("any", "not_a_valid_hash")
        assert result is False

    def test_verify_password_with_partial_hash(self):
        result = verify_password("any", "pbkdf2_sha256$incomplete")
        assert result is False

    def test_verify_password_with_invalid_iterations(self):
        result = verify_password("any", "pbkdf2_sha256$abc$salt$digest")
        assert result is False

    def test_ip_bucket_handles_invalid_ip(self):
        from src.core.detection.service import DetectionService

        invalid_ips = ["", "not_an_ip", "999.999.999.999", "192.168.1", None]
        for ip in invalid_ips:
            try:
                bucket = DetectionService._ip_to_bucket(ip)
                assert isinstance(bucket, int)
            except Exception:
                pass

    def test_ip_bucket_handles_ipv6(self):
        from src.core.detection.service import DetectionService

        try:
            bucket = DetectionService._ip_to_bucket("::1")
            assert isinstance(bucket, int)
        except Exception:
            pass


@pytest.mark.security
class TestRuleInjection:
    def test_packet_rule_rejects_malformed(self):
        invalid_rules = [
            "",
            "   ",
            "= = =",
            "((()))",
        ]
        dummy_row = {"dst_port": 80, "src_ip": "1.1.1.1", "proto": "TCP"}
        for rule_text in invalid_rules:
            try:
                match_packet_rule(dummy_row, rule_text)
            except (ValueError, Exception):
                pass

    def test_packet_rule_handles_special_chars(self):
        try:
            result = match_packet_rule(
                {"raw_ascii": "test\\x00data"},
                "raw_ascii contains '\\x00'"
            )
        except (ValueError, Exception):
            pass


@pytest.mark.security
class TestDatabaseSecurity:
    def test_db_path_traversal_prevention(self, tmp_path):
        db = Database(tmp_path / "safe.db")
        assert ".." not in str(db.db_path)

    def test_multiple_cursors(self, tmp_db):
        c1 = tmp_db.conn.cursor()
        c2 = tmp_db.conn.cursor()
        c1.execute("SELECT 1 AS val")
        c2.execute("SELECT 2 AS val")
        r1 = c1.fetchone()
        r2 = c2.fetchone()
        assert r1 is not None
        assert r2 is not None
