"""
The User module provides a class for representing a user with their associated username and public key.

Classes:
    User: Represents a user with their associated username and public key.
"""


class User:
    """
    Represents a user with their associated username and public key.

    Attributes:
        _username (str): The username of the user.
        _key: The key used for message encryption and decryption (optional).
        _online_status (bool): Indicates whether the user is online or offline.

    Properties:
        x25519_public_key (x25519.X25519PublicKey): The public key for the x25519 key exchange algorithm.
        username (str): The username of the user.
        key: The key used for message encryption and decryption.
        online_status (bool): Indicates whether the user is online or offline.

    Setter:
        key: Sets the key used for message encryption and decryption.
        online_status: Sets the online status of the user.

    """

    def __init__(self, username, x25519_public_key=None):
        """
        Initializes a User object with the specified username.

        Args:
            username (str): The username of the user.
        """
        self._username = username
        self._key = None
        self._online = True
        self._x25519_public_key = x25519_public_key

    @property
    def x25519_public_key(self):
        """
        x25519.X25519PublicKey: The public key for the x25519 key exchange algorithm.
        """
        return self._x25519_public_key

    @x25519_public_key.setter
    def x25519_public_key(self, value):
        """
        Sets the public key for the x25519 key exchange algorithm.

        Args:
            value (x25519.X25519PublicKey): The public key for the x25519 key exchange algorithm.
        """
        self._x25519_public_key = value

    @property
    def username(self):
        """
        str: The username of the user.
        """
        return self._username

    @property
    def key(self):
        """
        The key used for message encryption and decryption.
        """
        return self._key

    @key.setter
    def key(self, value):
        """
        Sets the key used for message encryption and decryption.

        Args:
            value: The key used for message encryption and decryption.
        """
        self._key = value

    @property
    def online(self):
        """
        bool: Indicates whether the user is online or offline.
        """
        return self._online

    @online.setter
    def online(self, value):
        """
        Sets the online status of the user.

        Args:
            value (bool): The online status of the user (True for online, False for offline).
        """
        self._online = value
