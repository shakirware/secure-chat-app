# potentially add token for each user logged in to send with each message to server.
# add token for login authentication.
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
from modules.database import ChatDatabase
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from modules.status_codes import StatusCode

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

MAX_CLIENTS = 5
DATABASE_FILE = './storage/chat.db'

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
        logging.info(f'Server started on {self.host}:{self.port}.')
        while True:
            client_socket_ssl, client_address = self.server_socket_ssl.accept()
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket_ssl,))
            client_thread.start()
            self.unauthenticated_clients[client_socket_ssl] = None  
            logging.info(f'New client connected from {client_address}.')

    def get_username_from_socket(self, client_socket_ssl):
        for username, client_data in self.authenticated_clients.items():
            if client_data['socket'] == client_socket_ssl:
                return username
        return None

    def handle_client(self, client_socket_ssl):
        is_running = True
        username = None
        while is_running:
            try:
                message = client_socket_ssl.recv(1024).decode('utf-8')
                if not message:
                    raise ValueError("Received an empty message.")
                sockets = [client_data['socket'] for client_data in self.authenticated_clients.values()]
                if client_socket_ssl in sockets:
                    self.handle_authenticated_message(message, client_socket_ssl)
                else:
                    self.handle_unauthenticated_message(message, client_socket_ssl)
                username = self.get_username_from_socket(client_socket_ssl)
            except:
                traceback.print_exc()
                if username in self.authenticated_clients:
                    del self.authenticated_clients[username]
                elif client_socket_ssl in self.unauthenticated_clients:
                    del self.unauthenticated_clients[client_socket_ssl]
                
                if username is not None:
                    self.send_notification(f'User {username} has logged out.') 
                
                logging.info(f"Client disconnected. Peer address: {client_socket_ssl.getpeername()}.")
                is_running = False
                #traceback.print_exc()
        
    def handle_authenticated_message(self, message, client_socket_ssl):
        data = json.loads(message)
        message_type = data.get('type')
        message_handlers = {
            'message': self.handle_message_user
        }    
        handler = message_handlers.get(message_type)
        if handler:
            handler(data, client_socket_ssl)
        else:
            self.send_status_response(StatusCode.INVALID_MESSAGE_TYPE, client_socket_ssl)
            logging.info(f'Received an invalid message type: {message_type}.')
        
    def handle_unauthenticated_message(self, message, client_socket_ssl):
        data = json.loads(message)
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
            self.send_status_response(StatusCode.INVALID_MESSAGE_TYPE, client_socket_ssl)
            logging.info(f'Received an invalid message type: {message_type}.')
     
    def handle_public_key(self, data, client_socket_ssl):
        base64_encoded_public_key = data.get('public_key')
        public_key_bytes = base64.b64decode(base64_encoded_public_key)
        public_key = X25519PublicKey.from_public_bytes(public_key_bytes)
        self.unauthenticated_clients[client_socket_ssl] = public_key
        public_key_pem = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        peer_address = client_socket_ssl.getpeername()
        logging.info(f'Public key received from {peer_address}: {public_key_pem}.')
     
    def handle_login(self, data, client_socket_ssl):
        username = data.get('username')
        password = data.get('password')
        
        if username in self.authenticated_clients:
            self.send_status_response(StatusCode.USERNAME_ALREADY_LOGGED_IN, client_socket_ssl)
            return
        
        if self.database.authenticate_user(username, password):
            self.authenticate_user(username, client_socket_ssl)
            logging.info(f"User '{username}' successfully authenticated.")
        else:
            self.send_status_response(StatusCode.INVALID_LOGIN, client_socket_ssl)
            logging.info("Authentication failed: Invalid login.")
    
    def authenticate_user(self, username, client_socket_ssl):
        self.authenticated_clients[username] = {'socket': client_socket_ssl, 'public_key': self.unauthenticated_clients[client_socket_ssl]}
        del self.unauthenticated_clients[client_socket_ssl]
        self.send_status_response(StatusCode.LOGIN_SUCCESSFUL, client_socket_ssl)
        self.broadcast_public_keys()
        self.send_notification(f'User {username} has logged in.')
        
    def handle_register(self, data, client_socket_ssl):
        username = data.get('username')
        password = data.get('password')
        
        if self.database.register_user(username, password):
            self.send_status_response(StatusCode.REGISTRATION_SUCCESSFUL, client_socket_ssl)
            logging.info(f'User Registered: {username}')
        else:
            self.send_status_response(StatusCode.USERNAME_ALREADY_EXISTS, client_socket_ssl)
            logging.info(f'User already exists {username}')
            
    def handle_message_user(self, data, client_socket_ssl):
        socket_to_username = {client_data['socket']: username for username, client_data in self.authenticated_clients.items()}
        sender = socket_to_username.get(client_socket_ssl)
        recipient = data.get('recipient')
        message_b64 = data.get('message')
        if recipient in self.authenticated_clients:
            recipient_socket_ssl = self.authenticated_clients[recipient]['socket']
            self.send_message(sender, recipient, message_b64, recipient_socket_ssl)
    
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
        
    def send_response(self, message, recipient_socket_ssl):
        data = {
            'type': 'server',
            'message': message,
            'timestamp': int(time.time())
        }
        json_data = json.dumps(data)
        recipient_socket_ssl.send(json_data.encode('utf-8'))
            
    def send_status_response(self, status_code, recipient_socket_ssl):
        data = {
            'type': 'server',
            'status_code': status_code,
            'timestamp': int(time.time())
        }
        json_data = json.dumps(data)
        recipient_socket_ssl.send(json_data.encode('utf-8'))
    
    def send_notification(self, message):
        for username, client_data in self.authenticated_clients.items():
            client_socket_ssl = client_data['socket']
            self.send_response(message, client_socket_ssl)
        
        
    def send_public_key(self, public_key, owner, recipient_socket_ssl):
        public_key_raw = public_key.public_bytes(
            encoding=Encoding.Raw, format=PublicFormat.Raw)
        public_key_b64 = base64.b64encode(public_key_raw).decode('utf-8')
        data = {
            'type': 'public_key',
            'owner': owner,
            'public_key': public_key_b64
        }
        json_data = json.dumps(data)
        recipient_socket_ssl.send(json_data.encode('utf-8'))
        
    def broadcast_public_keys(self):
        for public_key_username, client_data in self.authenticated_clients.items():
            client_socket_ssl = client_data['socket']
            public_key = client_data['public_key']
            
            for recipient_username, recipient_client_data in self.authenticated_clients.items():
                if recipient_username != public_key_username:
                    recipient_socket_ssl = recipient_client_data['socket']
                    self.send_public_key(public_key, public_key_username, recipient_socket_ssl)
        logging.info("Public keys broadcast initiated.")    

    def run(self):
        self.setup_server()
        self.run_server()
            
if __name__ == '__main__':
    certfile = './certs/server.crt'
    keyfile = './certs/server.key'
    server = ChatServer('localhost', 12100, certfile, keyfile)
    server.start()            