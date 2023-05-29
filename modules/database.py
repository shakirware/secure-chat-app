import sqlite3
import hashlib


class ChatDatabase:
    def __init__(self, db_file):
        self.db_file = db_file

    def register_user(self, username, password):
        with sqlite3.connect(self.db_file) as conn:
            c = conn.cursor()
            c.execute(
                "CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT)")
            hashed_password = hashlib.sha256(
                password.encode('utf-8')).hexdigest()
            try:
                c.execute("INSERT INTO users VALUES (?, ?)",
                          (username, hashed_password))
                conn.commit()
                return True
            except sqlite3.IntegrityError:
                return False

    def authenticate_user(self, username, password):
        with sqlite3.connect(self.db_file) as conn:
            c = conn.cursor()
            hashed_password = hashlib.sha256(
                password.encode('utf-8')).hexdigest()
            c.execute("SELECT * FROM users WHERE username=? AND password=?",
                      (username, hashed_password))
            if c.fetchone() is not None:
                return True
            else:
                return False
