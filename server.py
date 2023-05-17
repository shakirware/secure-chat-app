import threading
import socket
import ssl
import re
import logging
import base64
import traceback
import json
import time
import sys

from json.decoder import JSONDecodeError
from database import ChatDatabase
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

logging.basicConfig(level=logging.DEBUG)

MAX_CLIENTS = 5
MESSAGE_BUFFER_SIZE = 1024
DATABASE_FILE = 'chat.db'

class ChatServer(threading.Thread):
    def __init__(self, host, port, certfile, keyfile):
        super().__init__()
        self.host = host
        self.port = port
        self.certfile = certfile
        self.keyfile = keyfile
        self.unauthenticated_clients = {}
        self.authenticated_clients = {}
        self.database = ChatDatabase(DATABASE_FILE)
        
    def setup_server(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ssl_context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
        self.server_socket_ssl = self.ssl_context.wrap_socket(self.server_socket, server_side=True)
        self.server_socket_ssl.listen(MAX_CLIENTS)
        
    def run_server(self):
        logging.info(f'Server started on {self.host}:{self.port}')
        while True:
            client_socket_ssl, client_address = self.server_socket_ssl.accept()
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket_ssl,))
            client_thread.start()
            self.unauthenticated_clients[client_socket_ssl] = None  
            logging.info(f'New client connected from {client_address}')

    def handle_client(self, client_socket_ssl):
        is_running = True
        while is_running:
            try:
                message = client_socket_ssl.recv(MESSAGE_BUFFER_SIZE).decode('utf-8')
                sockets = [client_data['socket'] for client_data in self.authenticated_clients.values()]
                if client_socket_ssl in sockets:
                    self.handle_authenticated_message(message, client_socket_ssl)
                else:
                    self.handle_unauthenticated_message(message, client_socket_ssl)
            except:
                #traceback.print_exc()
                logging.info(f'Client Disconnected {client_socket_ssl.getpeername()}')
                if client_socket_ssl in self.authenticated_clients:
                    del self.authenticated_clients[client_socket_ssl]
                if client_socket_ssl in self.unauthenticated_clients:
                    del self.unauthenticated_clients[client_socket_ssl]
                is_running = False
        
    def handle_authenticated_message(self, message, client_socket_ssl):
        try:
            data = json.loads(message)
        except json.JSONDecodeError:
            self.send_message_from_server(f'The message format is invalid. Please ensure the message follows the required format and try again.', client_socket_ssl)
            logging.info('Invalid message format.')
            return
            
        message_type = data.get('type')
        message_handlers = {
            'message': self.handle_message_user
        }    
        
        handler = message_handlers.get(message_type)
        if handler:
            handler(data, client_socket_ssl)
        else:
            self.send_message_from_server('Invalid message type. Please ensure the message type is valid.', client_socket_ssl)
            logging.info(f'Invalid message type: {message_type}')
        
    def handle_unauthenticated_message(self, message, client_socket_ssl):
        try:
            data = json.loads(message)
        except (JSONDecodeError, ssl.SSLEOFError):
            self.send_message_from_server(f'The message format is invalid. Please ensure the message follows the required format and try again.', client_socket_ssl)
            logging.info('Invalid message format.')
            return
        
        message_type = data.get('type')
        message_handlers = {
            'register': self.handle_register,
            'login': self.handle_login,
            'public_key': self.handle_public_key,
        }
        
        handler = message_handlers.get(message_type)
        if handler:
            handler(data, client_socket_ssl)
        else:
            self.send_message_from_server('Invalid message type. Please ensure the message type is valid.', client_socket_ssl)
            logging.info(f'Invalid message type: {message_type}')
     
    def handle_public_key(self, data, client_socket_ssl):
        public_key_b64 = data.get('public_key')
        public_key_bytes = base64.b64decode(public_key_b64)
        public_key = x25519.X25519PublicKey.from_public_bytes(public_key_bytes)
        self.unauthenticated_clients[client_socket_ssl] = public_key
        logging.info(f'Public key received from {client_socket_ssl.getpeername()}: {public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)}')
     
    def handle_login(self, data, client_socket_ssl):
        username = data.get('username')
        password = data.get('password')
        
        if self.database.authenticate_user(username, password):
            self.authenticated_clients[username] = {'socket': client_socket_ssl, 'public_key': self.unauthenticated_clients[client_socket_ssl]}
            del self.unauthenticated_clients[client_socket_ssl]
            self.send_message_from_server(f'Login successful. Welcome {username}', client_socket_ssl)
            logging.info(f'User Logged In: {username}')
        else:
            self.send_message_from_server('The provided username or password is invalid. Please verify your credentials and try again.', client_socket_ssl)
            logging.info(f'Invalid Login')
    
    def handle_register(self, data, client_socket_ssl):
        username = data.get('username')
        password = data.get('password')
        
        if self.database.register_user(username, password):
            self.send_message_from_server('User registration completed successfully.', client_socket_ssl)
            logging.info(f'User Registered: {username}')
        else:
            self.send_message_from_server('The username provided is already in use. Please choose a different username.', client_socket_ssl)
            logging.info(f'User already exists {username}')
            
    def handle_message_user(self, data, client_socket_ssl):
        socket_to_username = {client_data['socket']: username for username, client_data in self.authenticated_clients.items()}
        sender = socket_to_username.get(client_socket_ssl)
        recipient = data.get('recipient')
        message_b64 = data.get('message')
        message = base64.b64decode(message_b64).decode('utf-8')
        
        if recipient in self.authenticated_clients:
            recipient_socket_ssl = self.authenticated_clients[recipient]['socket']
            self.send_message(sender, recipient, message, recipient_socket_ssl)
    
    def send_message(self, sender, recipient, message, recipient_socket_ssl):
        data = {
            'type': 'message',
            'sender': sender,
            'recipient': recipient,
            'message': message,
            'timestamp': int(time.time())
        }
        json_data = json.dumps(data)
        recipient_socket_ssl.send(json_data.encode('utf-8'))
        
    def send_message_from_server(self, message, recipient_socket_ssl):
        data = {
            'type': 'server',
            'message': message,
            'timestamp': int(time.time())
        }
        json_data = json.dumps(data)
        recipient_socket_ssl.send(json_data.encode('utf-8'))
        
     
    def run(self):
        self.setup_server()
        self.run_server()
            
if __name__ == '__main__':
    certfile = './certs/server.crt'
    keyfile = './certs/server.key'
    server = ChatServer('localhost', 12100, certfile, keyfile)
    server.start()            