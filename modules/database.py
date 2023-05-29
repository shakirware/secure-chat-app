import sqlite3
import hashlib
import random
import string


class ChatDatabase:
    def __init__(self, db_file):
        self.db_file = db_file

    def register_user(self, username, password):
        with sqlite3.connect(self.db_file) as conn:
            c = conn.cursor()
            c.execute(
                "CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, salt TEXT, password TEXT)")
            salt = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
            hashed_password = hashlib.sha256(
                (salt + password).encode('utf-8')).hexdigest()
            try:
                c.execute("INSERT INTO users VALUES (?, ?, ?)",
                          (username, salt, hashed_password))
                conn.commit()
                return True
            except sqlite3.IntegrityError:
                return False

    def authenticate_user(self, username, password):
        with sqlite3.connect(self.db_file) as conn:
            c = conn.cursor()
            c.execute("SELECT salt, password FROM users WHERE username=?",
                      (username,))
            result = c.fetchone()
            if result is not None:
                salt, hashed_password = result
                input_hashed_password = hashlib.sha256(
                    (salt + password).encode('utf-8')).hexdigest()
                if input_hashed_password == hashed_password:
                    return True
            return False
