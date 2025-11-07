import sqlite3
from contextlib import closing

DB_PATH = "app.db"

class Classes:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path

    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    # Legacy-style return for compatibility if needed
    def getUser(self, username):
        with closing(self._conn()) as conn, conn:
            cur = conn.execute("SELECT id, username, password FROM users WHERE username = ?", (username,))
            rows = cur.fetchall()
            return [(r['id'], r['username'], r['password']) for r in rows]

    def get_user_by_username(self, username):
        with closing(self._conn()) as conn, conn:
            cur = conn.execute("SELECT id, username, email, password, role, last_login FROM users WHERE username = ?", (username,))
            r = cur.fetchone()
            return dict(r) if r else None

    def get_user_by_username_email(self, username, email):
        with closing(self._conn()) as conn, conn:
            cur = conn.execute("SELECT id, username, email, role FROM users WHERE username = ? AND email = ?", (username, email))
            r = cur.fetchone()
            return dict(r) if r else None

    def get_all_user_ids(self):
        with closing(self._conn()) as conn, conn:
            cur = conn.execute("SELECT id FROM users")
            return [row['id'] for row in cur.fetchall()]

    def list_users(self):
        with closing(self._conn()) as conn, conn:
            cur = conn.execute("SELECT id, username, email, role, COALESCE(last_login, 'NULL') AS last_login FROM users ORDER BY id ASC")
            return [dict(r) for r in cur.fetchall()]

    def create_user(self, username, email, password, role='member'):
        with closing(self._conn()) as conn, conn:
            conn.execute(
                "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
                (username, email, password, role)
            )

    # Intentional IDOR sink: updates by provided id alone
    def update_user_password_by_id(self, user_id, new_password):
        with closing(self._conn()) as conn, conn:
            conn.execute("UPDATE users SET password = ? WHERE id = ?", (new_password, user_id))

    def record_login(self, user_id):
        with closing(self._conn()) as conn, conn:
            conn.execute("UPDATE users SET last_login = datetime('now') WHERE id = ?", (user_id,))

    def reset_last_login_all(self):
        with closing(self._conn()) as conn, conn:
            conn.execute("UPDATE users SET last_login = NULL")

    def reset_last_login_users(self, user_ids):
        if not user_ids:
            return
        placeholders = ",".join("?" for _ in user_ids)
        with closing(self._conn()) as conn, conn:
            conn.execute(f"UPDATE users SET last_login = NULL WHERE id IN ({placeholders})", user_ids)