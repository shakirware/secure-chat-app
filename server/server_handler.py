"""
This module provides a ServerHandler class that handles various server operations.

Module dependencies:
    - logging: Provides logging functionality.
    - base64: Provides base64 encoding and decoding functions.
    - common.encryption: Custom module for encryption-related operations.
    - server.req: Custom module for handling server requests.
    - server.database: Custom module for interacting with the database.

Classes:
    - ServerHandler: Handles server operations.

"""

import logging
import base64

from common.encryption import (
    rsa_public_key_to_pem, encrypt_session_token_with_rsa,
    generate_session_token, pem_to_rsa_public_key
)

import server.req as requests

from server.database import (
    get_rsa_public_key, authenticate_user,
    is_valid_credentials, register_user,
    store_rsa_public_key
)


class ServerHandler:
    """
    Handles server operations.

    Attributes:
        server (Server): An instance of the Server class representing the server.

    Methods:
        handle_register(packet, client): Handles the registration process for a client.
        handle_public_key_rsa(packet, client): Handles the storage of RSA public key for a client.
        handle_message_user(packet, client): Handles a message from a client to another client.
        handle_login(packet, client): Handles the login process for a client.
        notify_clients_user_logged_out(username): Notifies all clients that a user has logged out.
        notify_clients_user_logged_in(username): Notifies all clients that a user has logged in.
        notify_x25519_public_key(): Notifies all clients with the X25519 public key of connected clients.
    """

    def __init__(self, server):
        """
        Initializes a ServerHandler instance.

        Args:
            server (Server): An instance of the Server class representing the server.
        """
        self.server = server

    def handle_register(self, packet, client):
        """
        Handles the registration process for a client.

        Args:
            packet (Packet): An instance of the Packet class representing the received packet.
            client (Client): An instance of the Client class representing the connected client.
        """
        username = packet.username
        password = packet.password

        if is_valid_credentials(username, password):
            if register_user(username, password):
                log_message = f"Successfully registered user: {username}"
                requests.send_registration_success_response(
                    client.socket, packet)
            else:
                log_message = f"Failed to register user (already exists): {username}"
                requests.send_username_already_exists_response(
                    client.socket, packet)
        else:
            requests.send_weak_credentials_response(client.socket, packet)
            log_message = "Failed to register user (weak username and password)"

        logging.info(log_message)

    def handle_public_key_rsa(self, packet, client):
        """
        Handles the storage of RSA public key for a client.

        Args:
            packet (Packet): An instance of the Packet class representing the received packet.
            client (Client): An instance of the Client class representing the connected client.
        """
        rsa_public_pem = rsa_public_key_to_pem(
            base64.b64decode(packet.public_key))
        username = packet.username

        if store_rsa_public_key(username, rsa_public_pem):
            log_message = f"RSA Public Key stored in database for user: {username}"
            requests.send_rsa_public_key_stored(client.socket)
        else:
            log_message = f"Failed attempt to overwrite RSA Public Key for user: {username}"
            requests.send_rsa_public_key_not_stored(client.socket)

        logging.info(log_message)

    def handle_message_user(self, packet, client):
        """
        Handles a message from a client to another client.

        Args:
            packet (Packet): An instance of the Packet class representing the received packet.
            client (Client): An instance of the Client class representing the connected client.
        """
        token = base64.b64decode(packet.token)
        if token == client.token:
            recipient = next(
                (c for c in self.server.clients if c.username == packet.recipient), None)
            if recipient is not None:
                json_data = packet.to_json()
                recipient.socket.send(json_data.encode('utf-8'))
            else:
                # Recipient not found/not online
                return
        else:
            logging.info("Invalid token received from user '%s'.",
                         client.username)

    def handle_login(self, packet, client):
        """
        Handles the login process for a client.

        Args:
            packet (Packet): An instance of the Packet class representing the received packet.
            client (Client): An instance of the Client class representing the connected client.
        """
        username = packet.username

        if any(c.username == username for c in self.server.clients):
            requests.send_user_already_logged_in(client.socket)
            return

        if authenticate_user(username, packet.password):
            logging.info("User '%s' successfully authenticated.", username)
            client.authenticated = True
            client.username = username
            requests.send_login_success_response(client.socket, packet)

            client.x25519_public_key = base64.b64decode(packet.public_key)
            logging.info("X25519 Public Key for user '%s': %s",
                         client.username, client.x25519_public_key.hex())

            pem_rsa_public_key = get_rsa_public_key(username)
            client.rsa_public_key = pem_to_rsa_public_key(pem_rsa_public_key)

            client.token = generate_session_token()

            encrypted_token = encrypt_session_token_with_rsa(
                client.rsa_public_key, client.token)
            b64_encrypted_token = base64.b64encode(
                encrypted_token).decode('utf-8')
            requests.send_token(client.socket, b64_encrypted_token)
            logging.info("Session token generated for user '%s': %s",
                         username, client.token)

            self.server.clients.append(client)

            self.notify_clients_user_logged_in(username)
            self.notify_x25519_public_key()

    def notify_clients_user_logged_out(self, username):
        """
        Notifies all clients that a user has logged out.

        Args:
            username (str): The username of the user who has logged out.
        """
        sockets = [client.socket for client in self.server.clients]
        for socket in sockets:
            requests.send_user_logged_out_response(socket, username)

    def notify_clients_user_logged_in(self, username):
        """
        Notifies all clients that a user has logged in.

        Args:
            username (str): The username of the user who has logged in.
        """
        sockets = [client.socket for client in self.server.clients]
        for socket in sockets:
            requests.send_user_logged_in_response(socket, username)

    def notify_x25519_public_key(self):
        """
        Notifies all clients with the X25519 public key of connected clients.
        """
        for client in self.server.clients:
            target_clients = [r for r in self.server.clients if r != client]
            public_key_b64 = base64.b64encode(
                client.x25519_public_key).decode('utf-8')
            for target_client in target_clients:
                requests.send_x25519_public_key(
                    target_client.socket, public_key_b64, client.username)
        logging.info("Broadcasted X25519 Public Keys to all clients.")