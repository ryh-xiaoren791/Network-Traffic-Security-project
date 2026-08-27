from dataclasses import dataclass

from src.core.storage.db import Database, hash_password, is_password_hash, verify_password


@dataclass
class UserContext:
    username: str
    role: str
    must_change: bool = False


class AuthService:
    def __init__(self, db: Database) -> None:
        self.db = db

    def login(self, username: str, password: str) -> UserContext | None:
        c = self.db.conn.cursor()
        c.execute(
            "SELECT username, password, role, enabled, must_change FROM users WHERE username=?",
            (username,),
        )
        row = c.fetchone()
        if not row or row["enabled"] != 1:
            return None
        stored_password = str(row["password"] or "")
        if not verify_password(password, stored_password):
            return None
        if stored_password and not is_password_hash(stored_password):
            c.execute("UPDATE users SET password=? WHERE username=?", (hash_password(password), username))
            self.db.conn.commit()
        return UserContext(
            username=row["username"],
            role=row["role"],
            must_change=bool(row["must_change"]),
        )

    def change_password(self, username: str, old_password: str, new_password: str) -> bool:
        """校验旧密码后更新为新密码，并清除首次登录强制改密标记。"""
        if len(new_password) < 6 or new_password == old_password:
            return False
        c = self.db.conn.cursor()
        c.execute("SELECT username, password FROM users WHERE username=?", (username,))
        row = c.fetchone()
        if not row or not verify_password(old_password, str(row["password"] or "")):
            return False
        c.execute(
            "UPDATE users SET password=?, must_change=0 WHERE username=?",
            (hash_password(new_password), username),
        )
        self.db.conn.commit()
        return True
