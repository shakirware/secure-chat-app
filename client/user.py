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
        _x25519_public_key (x25519.X25519PublicKey): The public key for the x25519 key exchange algorithm.
        _key: The key used for message encryption and decryption (optional).

    Properties:
        x25519_public_key (x25519.X25519PublicKey): The public key for the x25519 key exchange algorithm.
        username (str): The username of the user.
        key: The key used for message encryption and decryption.

    Setter:
        key: Sets the key used for message encryption and decryption.

    """

    def __init__(self, username, x25519_public_key):
        """
        Initializes a User object with the specified username and x25519 public key.

        Args:
            username (str): The username of the user.
            x25519_public_key (x25519.X25519PublicKey): The public key for the x25519 key exchange algorithm.
        """
        self._username = username
        self._x25519_public_key = x25519_public_key
        self._key = None

    @property
    def x25519_public_key(self):
        """
        x25519.X25519PublicKey: The public key for the x25519 key exchange algorithm.
        """
        return self._x25519_public_key

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
