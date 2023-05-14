from database import ChatDatabase
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import threading
import socket
import ssl
import re
import logging
import base64

MAX_CLIENTS = 5
MESSAGE_BUFFER_SIZE = 1024
DATABASE_FILE = 'chat.db'

logging.basicConfig(level=logging.DEBUG)

class ChatServer(threading.Thread):
    def __init__(self, host, port, certfile, keyfile):
        super().__init__()
        self.host = host
        self.port = port
        self.certfile = certfile
        self.keyfile = keyfile
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ssl_context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
        self.server_socket_ssl = self.ssl_context.wrap_socket(self.server_socket, server_side=True)
        self.server_socket_ssl.listen(MAX_CLIENTS)
        self.clients = []
        self.authenticated_clients = {}
        self.database = ChatDatabase(DATABASE_FILE)
        
    def run(self):
        logging.info(f'Server started on {self.host}:{self.port}')
        while True:
            client_socket_ssl, client_address = self.server_socket_ssl.accept()
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket_ssl,))
            client_thread.start()
            self.clients.append(client_socket_ssl)
            logging.info(f'New client connected from {client_address}')
            
    def handle_client(self, client_socket_ssl):
        while True:
            try:
                message = client_socket_ssl.recv(MESSAGE_BUFFER_SIZE).decode('utf-8')
                if client_socket_ssl in self.authenticated_clients:
                    if message.startswith('/logout'):
                        self.logout_user(client_socket_ssl)
                        break
                    else:
                        self.broadcast(message, client_socket_ssl)
                else:
                    if message.startswith('/register'):
                        match = re.match(r'^/register (\S+) (\S+)$', message)
                        if match:
                            username, password = match.groups()
                            self.register_user(username, password, client_socket_ssl)
                    elif message.startswith('/login'):
                        match = re.match(r'^/login (\S+) (\S+)$', message)
                        if match:
                            username, password = match.groups()
                            self.authenticate_user(username, password, client_socket_ssl)
                        else:
                            client_socket_ssl.send('Invalid login command format.'.encode('utf-8'))
                    elif message.startswith('/public_key'):
                        public_key_b64 = message.split(maxsplit=1)[1]
                        public_key_bytes = base64.b64decode(public_key_b64)
                        public_key = x25519.X25519PublicKey.from_public_bytes(public_key_bytes)
                        logging.info(f'Public key received from {client_socket_ssl.getpeername()}: {public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)}')
                    else:
                        client_socket_ssl.send('You must be authenticated to send messages. Please log in or register.'.encode('utf-8'))
            except:
                del self.authenticated_clients[client_socket_ssl]
                self.clients.remove(client_socket_ssl)
                break
                
    def broadcast(self, message, client_socket_ssl):
        username = self.authenticated_clients[client_socket_ssl]
        failed_clients = []
        for authenticated_client_socket_ssl in self.authenticated_clients.keys():
            if authenticated_client_socket_ssl != client_socket_ssl:
                try:
                    authenticated_client_socket_ssl.send(f"{username}: {message}".encode('utf-8'))
                except:
                    failed_clients.append(authenticated_client_socket_ssl)
                    
        for client in failed_clients:
            self.clients.remove(client)
            del self.authenticated_clients[client]

        logging.info(f'Message broadcasted: {message} from {username}')
        
    def logout_user(self, client_socket_ssl):
        username = self.authenticated_clients[client_socket_ssl]
        del self.authenticated_clients[client_socket_ssl]
        self.clients.remove(client_socket_ssl)
        logging.info(f'User Logged Out: {username}')
        client_socket_ssl.send('You have been logged out.'.encode('utf-8'))
    
    def register_user(self, username, password, client_socket_ssl):
        if self.database.register_user(username, password):
            client_socket_ssl.send('User registered successfully.'.encode('utf-8'))
            logging.info('User Registered: {username}')
        else:
            client_socket_ssl.send('User already exists.'.encode('utf-8'))
        
    def authenticate_user(self, username, password, client_socket_ssl):
        if self.database.authenticate_user(username, password):
            client_socket_ssl.send('User logged in.'.encode('utf-8'))
            self.authenticated_clients[client_socket_ssl] = username
            logging.info(f'User Logged In: {username}')
        else:
            client_socket_ssl.send('Invalid username or password.'.encode('utf-8'))
        
                    
if __name__ == '__main__':
    certfile = './certs/server.crt'
    keyfile = './certs/server.key'
    server = ChatServer('localhost', 12100, certfile, keyfile)
    server.start()