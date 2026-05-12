from dataclasses import dataclass

from src.core.storage.db import Database, hash_password, is_password_hash, verify_password


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
        stored_password = str(row["password"] or "")
        if not verify_password(password, stored_password):
            return None
        if stored_password and not is_password_hash(stored_password):
            c.execute("UPDATE users SET password=? WHERE username=?", (hash_password(password), username))
            self.db.conn.commit()
        return UserContext(username=row["username"], role=row["role"])
