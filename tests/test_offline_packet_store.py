from __future__ import annotations

import unittest

from src.core.storage.offline_packet_store import OfflinePacketStore


class _FakeConn:
    def __init__(self, failing_sql: set[str] | None = None) -> None:
        self.failing_sql = set(failing_sql or set())
        self.calls: list[str] = []

    def execute(self, sql: str):
        self.calls.append(sql)
        if sql in self.failing_sql:
            raise RuntimeError(f"boom: {sql}")
        return self


class OfflinePacketStoreTests(unittest.TestCase):
    def test_disable_profiling_prefers_no_output(self) -> None:
        store = OfflinePacketStore.__new__(OfflinePacketStore)
        store.conn = _FakeConn()

        store._disable_profiling_output()

        self.assertEqual(store.conn.calls, ["PRAGMA enable_profiling='no_output';"])

    def test_disable_profiling_falls_back_to_off(self) -> None:
        store = OfflinePacketStore.__new__(OfflinePacketStore)
        store.conn = _FakeConn({"PRAGMA enable_profiling='no_output';"})

        store._disable_profiling_output()

        self.assertEqual(
            store.conn.calls,
            [
                "PRAGMA enable_profiling='no_output';",
                "PRAGMA enable_profiling='off';",
            ],
        )

    def test_execute_optional_swallows_non_critical_errors(self) -> None:
        store = OfflinePacketStore.__new__(OfflinePacketStore)
        store.conn = _FakeConn({"SET enable_progress_bar=false;"})

        store._execute_optional("SET enable_progress_bar=false;")

        self.assertEqual(store.conn.calls, ["SET enable_progress_bar=false;"])


if __name__ == "__main__":
    unittest.main()
