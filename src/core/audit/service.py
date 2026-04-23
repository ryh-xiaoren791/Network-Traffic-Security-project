from src.core.storage.db import Database, now_text


class AuditService:
    def __init__(self, db: Database) -> None:
        self.db = db

    def log(self, username: str, action: str, target: str, detail: str) -> None:
        c = self.db.conn.cursor()
        c.execute(
            "INSERT INTO audit_logs(ts, username, action, target, detail) VALUES(?,?,?,?,?)",
            (now_text(), username, action, target, detail),
        )
        self.db.conn.commit()

    def query(self, limit: int = 200, keyword: str = "", action: str = "") -> list[dict]:
        c = self.db.conn.cursor()
        sql = "SELECT * FROM audit_logs WHERE 1=1"
        args: list = []
        if keyword:
            sql += " AND (username LIKE ? OR target LIKE ? OR detail LIKE ?)"
            args.extend([f"%{keyword}%", f"%{keyword}%", f"%{keyword}%"])
        if action:
            sql += " AND action=?"
            args.append(action)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        c.execute(sql, tuple(args))
        return [dict(row) for row in c.fetchall()]

    def delete_log(self, log_id: int) -> None:
        c = self.db.conn.cursor()
        c.execute("DELETE FROM audit_logs WHERE id=?", (log_id,))
        self.db.conn.commit()

    def delete_logs(self, keyword: str = "", action: str = "") -> int:
        c = self.db.conn.cursor()
        sql = "DELETE FROM audit_logs WHERE 1=1"
        args: list = []
        if keyword:
            sql += " AND (username LIKE ? OR target LIKE ? OR detail LIKE ?)"
            args.extend([f"%{keyword}%", f"%{keyword}%", f"%{keyword}%"])
        if action:
            sql += " AND action=?"
            args.append(action)
        c.execute(sql, tuple(args))
        affected = c.rowcount
        self.db.conn.commit()
        return int(affected if affected is not None else 0)
