"""
Module: chat_database

This module provides a class for managing chat messages in an SQLite database.

Dependencies:
    - sqlite3

"""

import sqlite3

class ChatDatabase:
    """A class for managing chat messages in an SQLite database."""

    def __init__(self, username):
        """
        Initialize a ChatDatabase instance.

        Args:
            username (str): The username associated with the database.

        """
        self.db_file = f"./storage/{username}/messages.db"
        self.create_tables()

    def create_tables(self):
        """
        Create the necessary tables in the database if they don't exist.
        """
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()

            cursor.execute('''CREATE TABLE IF NOT EXISTS chat_messages
                              (id INTEGER PRIMARY KEY AUTOINCREMENT,
                               sender TEXT,
                               recipient TEXT,
                               message TEXT,
                               timestamp TEXT)''')

            cursor.execute('''CREATE TABLE IF NOT EXISTS latest_key
                              (user TEXT PRIMARY KEY,
                               key INTEGER)''')

    def insert_message(self, sender, recipient, message, timestamp):
        """
        Insert a new chat message into the database.

        Args:
            sender (str): The username of the message sender.
            recipient (str): The username of the message recipient.
            message (str): The content of the message.
            timestamp (str): The timestamp of the message.

        """
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()

            cursor.execute('''INSERT INTO chat_messages (sender, recipient, message, timestamp)
                              VALUES (?, ?, ?, ?)''', (sender, recipient, message, timestamp))

    def insert_key(self, user, key):
        """
        Insert or replace the latest encryption key for a user.

        Args:
            user (str): The username associated with the key.
            key (int): The latest encryption key.

        """
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()

            cursor.execute('''INSERT OR REPLACE INTO latest_key (user, key)
                              VALUES (?, ?)''', (user, key))

    def get_all_messages(self):
        """
        Retrieve all chat messages from the database.

        Returns:
            list: A list of tuples representing the chat messages.

        """
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()

            cursor.execute('''SELECT * FROM chat_messages''')
            messages = cursor.fetchall()

            return messages
