"""
This module provides a client handler class for handling client-side operations.

Module dependencies:
    - base64: The standard base64 module for encoding and decoding data.
    - logging: The standard logging module for logging messages and errors.
    - time: The standard time module for working with timestamps.
    - cryptography.hazmat.primitives.serialization: Provides functions for serializing cryptographic objects.
    - cryptography.hazmat.primitives.asymmetric.x25519: Provides X25519 key exchange functionality.
    - common.encryption: A custom module that provides encryption-related functions.
    - common.packet: A custom module that defines the Packet class for representing network packets.
    - common.status_codes: A custom module that defines status codes for network communication.
    - client.user: A custom module that defines the User class for representing users.
    - client.utils: A custom module that provides utility functions for the client.

Classes:
    - ClientHandler: Represents a client handler for handling client-side operations.
"""

import base64
import logging
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from common.encryption import (
    calculate_message_key, calculate_x25519_shared_secret,
    decrypt_message_with_aes, decrypt_session_token_with_rsa,
    encrypt_message_with_aes, generate_x25519_keypair
)
from common.packet import Packet
from common.status_codes import (
    INVALID_LOGIN, USERNAME_IN_USE, INVALID_MESSAGE_FORMAT,
    INVALID_MESSAGE_TYPE, USERNAME_ALREADY_LOGGED_IN,
    USERNAME_ALREADY_EXISTS, USER_LOGGED_IN, WEAK_CREDENTIALS,
    RSA_PUBLIC_KEY_STORED, RSA_PUBLIC_KEY_NOT_STORED,
    USER_LOGGED_OUT, LOGIN_SUCCESSFUL, REGISTRATION_SUCCESSFUL
)

from client.user import User

from client.utils import generate_and_send_rsa_public_key, load_rsa_private_key


class ClientHandler:
    """
    The ClientHandler class represents a client handler for handling client-side operations.

    Attributes:
        client (Client): The associated client instance.
        x25519_public_key (x25519.X25519PublicKey): The client's X25519 public key.
        x25519_private_key (x25519.X25519PrivateKey): The client's X25519 private key.
        token (bytes): The session token received from the server.
        username (str): The username of the client.
        users (list): A list of connected user instances.

    Methods:
        - handle_message_user(packet): Handles a message from another user.
        - handle_login(username, password): Handles the login process.
        - handle_register(username, password): Handles the registration process.
        - handle_message_server(packet): Handles a message from the server.
        - handle_token(packet): Handles the session token received from the server.
        - handle_public_key(packet): Handles a public key received from another user.
        - send_encrypted_message(recipient_username, message): Sends an encrypted message to a recipient.
        - get_user_key(msg_username): Retrieves the encryption key for a user.
    """

    def __init__(self, client):
        """
        Initialize the ClientHandler instance.

        Args:
            client (Client): The client instance associated with the handler.

        """
        self.client = client
        self.x25519_public_key = None
        self.x25519_private_key = None
        self.token = None
        self.username = None
        self.users = []

    def handle_message_user(self, packet):
        """
        Handles a message from another user.

        Args:
            packet (Packet): The packet containing the message.

        Returns:
            None
        """
        key = self.get_user_key(packet.sender)
        message = decrypt_message_with_aes(packet.message, key)
        # store message in database
        logging.info('%s: %s', packet.sender, message)

    def handle_login(self, username, password):
        """
        Handles the login process.

        Args:
            username (str): The username for login.
            password (str): The password for login.

        Returns:
            None
        """
        self.x25519_private_key, self.x25519_public_key = generate_x25519_keypair()
        x25519_public_key_raw = self.x25519_public_key.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        x25519_public_key_b64 = base64.b64encode(
            x25519_public_key_raw).decode('utf-8')
        packet = Packet('login', username=username,
                        password=password, public_key=x25519_public_key_b64)
        self.client.message_queue.put(packet)

    def handle_register(self, username, password):
        """
        Handles the registration process.

        Args:
            username (str): The desired username for registration.
            password (str): The desired password for registration.

        Returns:
            None
        """
        packet = Packet('register', username=username, password=password)
        self.client.message_queue.put(packet)

    def handle_message_server(self, packet):
        """
        Handles a message from the server.

        Args:
            packet (Packet): The packet containing the message.

        Returns:
            None
        """
        if packet.status_code == REGISTRATION_SUCCESSFUL:
            logging.info("Registration was successful.")
            generate_and_send_rsa_public_key(
                packet.username, self.client.message_queue
            )
        elif packet.status_code == LOGIN_SUCCESSFUL:
            logging.info("Login was successful.")
            self.username = packet.username
        elif packet.status_code == USER_LOGGED_OUT:
            for user in self.users:
                if user.username == packet.username:
                    self.users.remove(user)
                    logging.info("User '%s' has logged out.", packet.username)
                    break

    def handle_token(self, packet):
        """
        Handles the session token received from the server.

        Args:
            packet (Packet): The packet containing the session token.

        Returns:
            None
        """
        encrypted_token = base64.b64decode(packet.token)
        rsa_private_key = load_rsa_private_key(
            f"./storage/{self.username}/rsa_private_key.pem"
        )
        self.token = decrypt_session_token_with_rsa(
            rsa_private_key, encrypted_token)
        logging.info('Token received from server: %s', self.token)

    def handle_public_key(self, packet):
        """
        Handles a public key received from another user.

        Args:
            packet (Packet): The packet containing the public key.

        Returns:
            None
        """
        x25519_public_key_bytes = base64.b64decode(packet.public_key)
        x25519_public_key = x25519.X25519PublicKey.from_public_bytes(
            x25519_public_key_bytes
        )
        user = User(packet.owner, x25519_public_key)
        self.users.append(user)
        logging.info(
            "Public Key from User '%s' has been stored.", packet.owner)

    def send_encrypted_message(self, recipient_username, message):
        """
        Sends an encrypted message to a recipient.

        Args:
            recipient_username (str): The username of the recipient.
            message (str): The message to be sent.

        Returns:
            None
        """
        key = self.get_user_key(recipient_username)
        encrypted_message_b64 = encrypt_message_with_aes(
            message, key)
        token_b64 = base64.b64encode(self.token).decode('utf-8')
        packet = Packet(
            'message',
            sender=self.username,
            recipient=recipient_username,
            message=encrypted_message_b64,
            token=token_b64,
            timestamp=int(time.time()),
        )
        self.client.message_queue.put(packet)
        # also need to store message
        logging.info('%s: %s', self.username, message)

    def get_user_key(self, msg_username):
        """
        Retrieves the encryption key for a user.

        Args:
            msg_username (str): The username of the user.

        Returns:
            bytes: The encryption key for the user.
        """
        msg_user = next(
            (user for user in self.users if user.username == msg_username), None)
        if not msg_user:
            logging.info("User '%s' not found.", msg_username)
            return None
        if not msg_user.key:
            shared_secret = calculate_x25519_shared_secret(
                self.x25519_private_key, msg_user.x25519_public_key)
            key = calculate_message_key(shared_secret)
        else:
            key = calculate_message_key(msg_user.key)
        msg_user.key = key
        return key
