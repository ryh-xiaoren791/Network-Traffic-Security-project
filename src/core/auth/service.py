from dataclasses import dataclass

from src.core.storage.db import Database


@dataclass
class UserContext:
    username: str
    role: str


class AuthService:
    def __init__(self, db: Database) -> None:
        self.db = db

    def login(self, username: str, password: str) -> UserContext | None:
        c = self.db.conn.cursor()
        c.execute("SELECT username, password, role, enabled FROM users WHERE username=?", (username,))
        row = c.fetchone()
        if not row or row["enabled"] != 1:
            return None
        if password != str(row["password"]):
            return None
        return UserContext(username=row["username"], role=row["role"])
