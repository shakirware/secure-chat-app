"""
This module defines the Client class representing a connected client.

Classes:
    Client: Represents a connected client.

Attributes:
    - socket (socket): The client's socket connection.
    - rsa_public_key (str): The RSA public key associated with the client.
    - x25519_public_key (str): The X25519 public key associated with the client.
    - authenticated (bool): Flag indicating if the client is authenticated.
    - username (str): The username of the client.
    - token (str): The session token associated with the client.

Methods:
    - __init__(self, client_socket_ssl): Initializes a new instance of the Client class.
"""

class Client:
    """
    Represents a connected client.
    """

    def __init__(self, client_socket_ssl):
        """
        Initializes a new instance of the Client class.

        Args:
            client_socket_ssl (socket): The SSL socket connection with the client.
        """
        self._socket = client_socket_ssl
        self._username = None
        self._rsa_public_key = None
        self._x25519_public_key = None
        self._authenticated = False
        self._token = None

    @property
    def socket(self):
        """
        Get the client's socket.

        Returns:
            socket: The client's socket connection.
        """
        return self._socket

    @property
    def rsa_public_key(self):
        """
        Get the RSA public key associated with the client.

        Returns:
            str: The RSA public key.
        """
        return self._rsa_public_key

    @rsa_public_key.setter
    def rsa_public_key(self, value):
        """
        Set the RSA public key associated with the client.

        Args:
            value (str): The RSA public key to set.
        """
        self._rsa_public_key = value

    @property
    def x25519_public_key(self):
        """
        Get the X25519 public key associated with the client.

        Returns:
            str: The X25519 public key.
        """
        return self._x25519_public_key

    @x25519_public_key.setter
    def x25519_public_key(self, value):
        """
        Set the X25519 public key associated with the client.

        Args:
            value (str): The X25519 public key to set.
        """
        self._x25519_public_key = value

    @property
    def authenticated(self):
        """
        Check if the client is authenticated.

        Returns:
            bool: True if the client is authenticated, False otherwise.
        """
        return self._authenticated

    @authenticated.setter
    def authenticated(self, value):
        """
        Set the authentication status of the client.

        Args:
            value (bool): The authentication status to set.
        """
        self._authenticated = value

    @property
    def username(self):
        """
        Get the username of the client.

        Returns:
            str: The username.
        """
        return self._username

    @username.setter
    def username(self, value):
        """
        Set the username of the client.

        Args:
            value (str): The username to set.
        """
        self._username = value

    @property
    def token(self):
        """
        Get the session token associated with the client.

        Returns:
            str: The session token.
        """
        return self._token

    @token.setter
    def token(self, value):
        """
        Set the session token associated with the client.

        Args:
            value (str): The session token to set.
        """
        self._token = value
