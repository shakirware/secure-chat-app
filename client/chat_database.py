"""
This module provides a class for managing chat messages in an SQLite database.

Dependencies:
    - sqlite3

Classes:
    - ChatDatabase: A class for managing chat messages in an SQLite database.

"""

import sqlite3

from common.constants import CLIENT_DATABASE_FILE

from client.user import User

from client.group import Group


class ChatDatabase:
    """
    A class for managing chat messages in an SQLite database.

    Args:
        username (str): The username associated with the database.

    Attributes:
        username (str): The username associated with the database.
        db_file (str): The file path of the SQLite database file.

    Methods:
        - __init__(self, username): Initialize a ChatDatabase instance.
        - create_tables(self): Create the necessary tables in the database.
        - insert_message(self, sender, recipient, message): Insert a new message into the database.
        - get_messages(self, username): Retrieve messages for the specified username.
        - delete_messages(self, username): Delete all messages for the specified username.
    """

    def __init__(self, username):
        """
        Initialize a ChatDatabase instance.

        Args:
            username (str): The username associated with the database.

        """
        self.username = username
        self.db_file = CLIENT_DATABASE_FILE.format(username=username)
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
                               
            cursor.execute('''CREATE TABLE IF NOT EXISTS group_messages
                              (id INTEGER PRIMARY KEY AUTOINCREMENT,
                               members TEXT,
                               sender TEXT,
                               recipient TEXT,
                               message TEXT,
                               timestamp TEXT)''')

            cursor.execute('''CREATE TABLE IF NOT EXISTS latest_key
                              (user TEXT PRIMARY KEY,
                               key INTEGER)''')

            cursor.execute('''CREATE TABLE IF NOT EXISTS latest_group_key
                              (group_name TEXT,
                               member TEXT,
                               key INTEGER,
                               PRIMARY KEY (group_name, member))''')

    def insert_group_message(self, members, sender, recipient, message, timestamp):
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()
            
            members_str = ",".join(members)
            
            cursor.execute("INSERT INTO group_messages (members, sender, recipient, message, timestamp) VALUES (?, ?, ?, ?, ?)",
                       (members_str, sender, recipient, message, timestamp))
            

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
            user (User): The User object associated with the key.
            key (int): The latest encryption key.
        """
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()

            cursor.execute('''INSERT OR REPLACE INTO latest_key (user, key)
                              VALUES (?, ?)''', (user.username, key))

    def insert_group(self, group):
        """
        Insert a Group object in the database.

        Args:
            group (Group): The Group object to store.

        """
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()

            for member, key in group.member_keys.items():
                cursor.execute('''INSERT OR REPLACE INTO latest_group_key (group_name, member, key)
                                  VALUES (?, ?, ?)''', (group.name, member, key))
                                  
    def get_all_group_messages(self):
        """
        Retrieve all group messages from the database and store them in a dictionary.

        Returns:
            dict: A dictionary containing arrays of messages for each group.

        """
        group_messages = {}

        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()

            cursor.execute('''SELECT DISTINCT members FROM group_messages''')
            groups = cursor.fetchall()

            for group in groups:
                members = group[0]
                
                cursor.execute('''SELECT sender, recipient, message, timestamp
                                  FROM group_messages
                                  WHERE members = ?
                                  ORDER BY timestamp''',
                               (members,))
                messages = cursor.fetchall()
                group_messages[members] = messages

        return group_messages



    def get_all_messages(self):
        """
        Retrieve all messages from the database and store them in a dictionary.

        Returns:
            dict: A dictionary containing arrays of messages for each username.

        """
        messages = {}

        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()

            cursor.execute(
                '''SELECT DISTINCT sender FROM chat_messages WHERE sender != ?''', (self.username,))
            senders = cursor.fetchall()

            cursor.execute(
                '''SELECT DISTINCT recipient FROM chat_messages WHERE recipient != ?''', (self.username,))
            recipients = cursor.fetchall()

            usernames = set([username[0] for username in senders + recipients])

            for username in usernames:
                cursor.execute('''SELECT sender, recipient, message, timestamp
                                  FROM chat_messages
                                  WHERE (sender = ? AND recipient = ?)
                                  OR (sender = ? AND recipient = ?)
                                  ORDER BY timestamp''',
                               (self.username, username, username, self.username))
                chat = cursor.fetchall()
                messages[username] = chat

        return messages
    
    def get_all_groups(self):
        """
        Retrieve all groups from the database and return an array of Group objects.

        Returns:
            list: An array of Group objects.

        """
        groups = []

        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()

            # Retrieve unique group names
            cursor.execute(
                '''SELECT DISTINCT group_name FROM latest_group_key''')
            group_names = cursor.fetchall()

            # Retrieve member keys for each group
            for group_name in group_names:
                cursor.execute(
                    '''SELECT member, key FROM latest_group_key WHERE group_name = ?''', (group_name[0],))
                members = group_name[0].split(',')
                group = Group(members)
                group.member_keys = {row[0]: row[1]
                                     for row in cursor.fetchall()}
                groups.append(group)

        return groups

    def get_all_users(self):
        """
        Retrieve all users from the database and return a list of User objects.

        Returns:
            list: A list of User objects.
        """
        users = []

        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()

            cursor.execute('''SELECT user, key FROM latest_key''')
            rows = cursor.fetchall()

            for username, key in rows:
                user = User(username, None)
                user.key = key
                user.online = False
                users.append(user)

        return users
