"""
This module provides a ServerDatabase class that handles various server database operations.

Module dependencies:
    - sqlite3: Provides the interface for interacting with SQLite databases.
    - hashlib: Provides hash functions for password hashing.
    - random: Provides functions for generating random data.
    - string: Provides string constants for generating random data.
    - os: Provides functions for interacting with the operating system.

Classes:
    - ServerDatabase: Handles server database operations.

"""

import sqlite3
import hashlib
import random
import string
import os


class ServerDatabase:
    """
    A class for handling server database operations.

    Methods:
        - register_user(username, password): Registers a new user in the database.
        - authenticate_user(username, password): Authenticates a user with the provided username and password.
        - store_rsa_public_key(username, rsa_public_key): Stores the RSA public key for a user in the database.
        - get_rsa_public_key(username): Retrieves the RSA public key for a user from the database.
        - is_valid_credentials(username, password): Checks if the provided username and password meet the minimum length requirements.
    """

    def __init__(self, db_file):
        """
            Initialize a ChatDatabase instance.

            Args:
                username (str): The username associated with the database.

            """
        self.db_file = db_file

    def register_user(self, username, password):
        """
        Registers a new user in the database.

        Args:
            username (str): The username of the user.
            password (str): The password of the user.

        Returns:
            bool: True if the user is successfully registered, False if the username already exists.
        """
        with sqlite3.connect(self.db_file) as conn:
            c = conn.cursor()
            c.execute(
                "CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, salt TEXT, password TEXT)")

            salt = ''.join(random.choices(
                string.ascii_letters + string.digits, k=16))
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
        """
        Authenticates a user with the provided username and password.

        Args:
            username (str): The username of the user.
            password (str): The password of the user.

        Returns:
            bool: True if the authentication is successful, False otherwise.
        """
        with sqlite3.connect(self.db_file) as conn:
            c = conn.cursor()
            c.execute(
                "SELECT salt, password FROM users WHERE username=?", (username,))
            result = c.fetchone()

            if result is not None:
                salt, hashed_password = result
                input_hashed_password = hashlib.sha256(
                    (salt + password).encode('utf-8')).hexdigest()

                if input_hashed_password == hashed_password:
                    return True
            return False

    def store_rsa_public_key(self, username, rsa_public_key):
        """
        Stores the RSA public key for a user in the database.

        Args:
            username (str): The username of the user.
            rsa_public_key (str): The RSA public key of the user.

        Returns:
            bool: True if the RSA public key is successfully stored, False if the username already exists.
        """
        with sqlite3.connect(self.db_file) as conn:
            c = conn.cursor()
            c.execute(
                "CREATE TABLE IF NOT EXISTS rsa_public_keys (username TEXT PRIMARY KEY, public_key TEXT)")

            try:
                c.execute("INSERT INTO rsa_public_keys (username, public_key) VALUES (?, ?)",
                          (username, rsa_public_key))
                conn.commit()
                return True
            except sqlite3.IntegrityError:
                return False

    def get_rsa_public_key(self, username):
        """
        Retrieves the RSA public key for a user from the database.

        Args:
            username (str): The username of the user.

        Returns:
            str or None: The RSA public key if found, None otherwise.
        """
        with sqlite3.connect(self.db_file) as conn:
            c = conn.cursor()
            c.execute(
                "SELECT public_key FROM rsa_public_keys WHERE username = ?", (username,))
            result = c.fetchone()

            if result is not None:
                public_key = result[0]
                return public_key

            return None

    def is_valid_credentials(self, username, password):
        """
        Checks if the provided username and password meet the minimum length requirements.

        Args:
            username (str): The username to be checked.
            password (str): The password to be checked.

        Returns:
            bool: True if the username and password meet the minimum length requirements, False otherwise.
        """
        return len(username) >= 4 and len(password) >= 4
