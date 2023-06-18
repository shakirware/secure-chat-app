"""
This module implements a server that handles client connections and messages.

Module dependencies:
    - logging: Provides logging functionality.
    - socket: Provides network communication through sockets.
    - ssl: Provides SSL/TLS functionality.
    - threading: Provides multi-threading support.
    - json: Provides JSON encoding and decoding functions.
    - common.packet: Custom module for packet handling.
    - server.req: Custom module for handling server requests.
    - server.client: Custom module for representing client connections.
    - server.server_handler: Custom module for handling server operations.

Classes:
    - Server: Represents a server that handles client connections and messages.

"""

import logging
import socket
import ssl
import threading
import json

from common.packet import Packet

import server.req as requests

from server.client import Client
from server.server_handler import ServerHandler


logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s [%(levelname)s] %(message)s')


class Server(threading.Thread):
    """
    Represents a server that handles client connections and messages.

    Attributes:
        host (str): The host address of the server.
        port (int): The port number on which the server listens.
        certfile (str): Path to the SSL certificate file.
        keyfile (str): Path to the SSL key file.
        clients (list): A list of connected client instances.
        server_handler (ServerHandler): An instance of the server handler.

    Methods:
        handle_client(client): Handles a connected client.
        handle_unauthenticated_message(packet, client): Handles an unauthenticated message from a client.
        handle_authenticated_message(packet, client): Handles an authenticated message from a client.
        run(): Starts the server and listens for client connections.
    """

    def __init__(self, host, port, certfile, keyfile):
        """
        Initializes a Server instance.

        Args:
            host (str): The host address of the server.
            port (int): The port number on which the server listens.
            certfile (str): Path to the SSL certificate file.
            keyfile (str): Path to the SSL key file.
        """
        super().__init__()
        self.host = host
        self.port = port
        self.certfile = certfile
        self.keyfile = keyfile
        self.clients = []
        self.server_handler = ServerHandler(self)

    def handle_client(self, client):
        """
        Handles a connected client.

        Args:
            client (Client): An instance of the Client class representing the connected client.
        """
        while True:
            try:
                message = client.socket.recv(1024).decode('utf-8')
                packet = Packet.from_json(message)

                if not message:
                    break

                if client.authenticated:
                    self.handle_authenticated_message(packet, client)
                else:
                    self.handle_unauthenticated_message(packet, client)

            except json.decoder.JSONDecodeError:
                break

        if client.authenticated:
            self.clients.remove(client)
            self.server_handler.notify_clients_user_logged_out(client.username)

        logging.info("Client disconnected. Peer address: %s.",
                     client.socket.getpeername())

    def handle_unauthenticated_message(self, packet, client):
        """
        Handles an unauthenticated message from a client.

        Args:
            packet (Packet): An instance of the Packet class representing the received packet.
            client (Client): An instance of the Client class representing the connected client.
        """
        if packet.packet_type == 'register':
            self.server_handler.handle_register(packet, client)
        elif packet.packet_type == 'login':
            self.server_handler.handle_login(packet, client)
        elif packet.packet_type == 'public_key_rsa':
            self.server_handler.handle_public_key_rsa(packet, client)
        else:
            requests.send_invalid_message_type_response(client.socket)
            logging.info("Received an invalid message type: %s.",
                         packet.packet_type)

    def handle_authenticated_message(self, packet, client):
        """
        Handles an authenticated message from a client.

        Args:
            packet (Packet): An instance of the Packet class representing the received packet.
            client (Client): An instance of the Client class representing the connected client.
        """
        if packet.packet_type == 'message':
            self.server_handler.handle_message_user(packet, client)
        elif packet.packet_type == 'group':
            self.server_handler.handle_message_user(packet, client)
        elif packet.packet_type == 'login':
            requests.send_user_already_logged_in(client.socket)
        elif packet.packet_type == 'logout':
            self.server_handler.handle_logout(packet, client)
        else:
            requests.send_invalid_message_type_response(client.socket)
            logging.info("Received an invalid message type: %s.",
                         packet.packet_type)

    def run(self):
        """
        Starts the server and listens for client connections.
        """
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(
            certfile=self.certfile, keyfile=self.keyfile)

        with socket.create_server((self.host, self.port)) as server_socket:
            with ssl_context.wrap_socket(server_socket, server_side=True) as server_socket_ssl:
                logging.info('Server started on %s:%s.', self.host, self.port)
                while True:
                    client_socket_ssl, client_address = server_socket_ssl.accept()
                    logging.info('New client connected from %s.',
                                 client_address)

                    client = Client(client_socket_ssl)
                    client_thread = threading.Thread(
                        target=self.handle_client, args=(client,))
                    client_thread.start()
