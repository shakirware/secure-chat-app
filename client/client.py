"""
This module provides a client implementation for connecting to a server and exchanging messages.

Module dependencies:
    - logging: The standard logging module for logging messages and errors.
    - socket: The standard socket module for creating network sockets.
    - ssl: The standard ssl module for establishing secure connections.
    - threading: The standard threading module for managing concurrent execution.
    - traceback: The standard traceback module for printing detailed exception information.
    - queue: The standard queue module for managing message queues.
    - common.packet: A custom module that defines the Packet class for representing network packets.
    - client.client_handler: A custom module that implements the ClientHandler class for handling client-side operations.
    
Classes:
     - Client: Represents a client that connects to a server and exchanges messages.
"""

import logging
import socket
import ssl
import threading
import traceback

from queue import Empty, Queue

from common.packet import Packet
from client.client_handler import ClientHandler


logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s [%(levelname)s] %(message)s')


class Client(threading.Thread):
    """
    The Client class represents a client that connects to a server and exchanges messages.

    Args:
        host (str): The hostname or IP address of the server.
        port (int): The port number to connect to on the server.
        certfile (str): The path to the certificate file for verifying the server's identity.
        interface (str): The network interface to bind the client socket to (optional).

    Attributes:
        host (str): The hostname or IP address of the server.
        port (int): The port number to connect to on the server.
        cert_file (str): The path to the certificate file for verifying the server's identity.
        interface (str): The network interface to bind the client socket to.
        message_queue (Queue): A thread-safe queue for storing outgoing messages.
        handler (ClientHandler): An instance of the ClientHandler class for handling client-side operations.
        running (bool): A flag indicating whether the client is running.
        socket_ssl (ssl.SSLSocket): The SSL socket used for communication with the server.

    Methods:
        - send_messages(): Continuously retrieves messages from the message queue and sends them to the server.
        - receive_messages(): Continuously receives messages from the server and handles them accordingly.
        - get_user_input(): Waits for user input and performs the corresponding actions based on the input.
        - run(): The main execution method of the client thread.
    """

    def __init__(self, host, port, certfile, interface=None):
        super().__init__()
        self.host = host
        self.port = port
        self.cert_file = certfile
        self.interface = interface
        self.message_queue = Queue()
        self.handler = ClientHandler(self)
        self.running = True
        self.socket_ssl = None

    def send_messages(self):
        """
        Continuously retrieves messages from the message queue and sends them to the server.

        This method runs in a separate thread to enable concurrent sending of messages.
        """
        while self.running:
            try:
                packet = self.message_queue.get(timeout=1)
                self.socket_ssl.send(packet.to_json().encode())
                self.message_queue.task_done()
            except Empty:
                continue

    def receive_messages(self):
        """
        Continuously receives messages from the server and handles them accordingly.

        This method runs in a separate thread to enable concurrent receiving of messages.
        """
        while self.running:
            try:
                message = self.socket_ssl.recv(1024).decode()
                if not message:
                    break

                packet = Packet.from_json(message)

                if packet.packet_type == 'token':
                    self.handler.handle_token(packet)
                elif packet.packet_type == 'message':
                    self.handler.handle_message_user(packet)
                elif packet.packet_type == 'group':
                    self.handler.handle_message_group(packet)
                elif packet.packet_type == 'server':
                    self.handler.handle_message_server(packet)
                elif packet.packet_type == 'public_key':
                    self.handler.handle_public_key(packet)
                elif packet.packet_type == 'offline':
                    self.handler.handle_offline_messages(packet)
                else:
                    logging.info('Invalid packet type.')

                logging.info('Received packet: %s', packet.to_json())
            except Exception as error:
                traceback.print_exc()
                logging.error(
                    'Error occurred while receiving messages: %s', error)
                break

    def get_user_input(self):
        """
        Waits for user input and performs the corresponding actions based on the input.

        This method runs in a separate thread to enable concurrent handling of user input.
        """
        while self.running:
            try:
                input_str = input()
                command, *args = input_str.split()

                if command.lower() == "/msg" and len(args) >= 2:
                    recipient = args[0]
                    message = ' '.join(args[1:])
                    self.handler.send_encrypted_message(message, recipient)
                elif command.lower() == "/group" and len(args) >= 2:
                    members = sorted(list(set(args[0].split(','))))
                    message = ' '.join(args[1:])
                    self.handler.send_group_message(message, members) 
                elif command.lower() == "/login" and len(args) == 2:
                    username = args[0]
                    password = args[1]
                    self.handler.handle_login(username, password)
                elif command.lower() == "/register" and len(args) == 2:
                    username = args[0]
                    password = args[1]
                    self.handler.handle_register(username, password)
                elif command.lower() == "/logout":
                    self.handler.handle_logout()
                else:
                    logging.error("Invalid Command or Insufficient Arguments.")
            except EOFError:
                self.running = False

    def run(self):
        """
        The main execution method of the client thread.

        It establishes a secure connection with the server, starts the send and receive threads,
        and waits for user input until the client is terminated.
        """
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_context.load_verify_locations(self.cert_file)

        with socket.create_connection((self.host, self.port), self.interface) as client_socket:
            with ssl_context.wrap_socket(client_socket, server_hostname=self.host) as socket_ssl:
                logging.info("Connection established with the server.")
                self.socket_ssl = socket_ssl

                receive_thread = threading.Thread(target=self.receive_messages)
                receive_thread.start()

                send_thread = threading.Thread(target=self.send_messages)
                send_thread.start()

                self.get_user_input()

        receive_thread.join()
        send_thread.join()
