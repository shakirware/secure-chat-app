import threading
import socket
import ssl
import re
import logging
from database import ChatDatabase

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
        self.server_socket_ssl.listen(5)
        self.clients = []
        self.authenticated_clients = {}
        self.db = ChatDatabase('chat.db')
        
    def run(self):
        logging.info('Server started on {}:{}'.format(self.host, self.port))
        while True:
            client_socket_ssl, client_address = self.server_socket_ssl.accept()
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket_ssl,))
            client_thread.start()
            self.clients.append(client_socket_ssl)
            logging.info('New client connected from {}'.format(client_address))
            
    def handle_client(self, client_socket_ssl):
        while True:
            try:
                message = client_socket_ssl.recv(1024).decode('utf-8')
                
                if client_socket_ssl in self.authenticated_clients:
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
                    else:
                        client_socket_ssl.send('You must be authenticated to send messages. Please log in or register.'.encode('utf-8'))
            except:
                del self.authenticated_clients[client_socket_ssl]
                self.clients.remove(client_socket_ssl)
                break
        logging.info('Client disconnected')
                
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

        logging.info('Message broadcasted: {} from {}'.format(message, username))
    
    def register_user(self, username, password, client_socket_ssl):
        if self.db.register_user(username, password):
            client_socket_ssl.send('User registered successfully.'.encode('utf-8'))
            logging.info('User Registered: {}'.format(username))
        else:
            client_socket_ssl.send('User already exists.'.encode('utf-8'))
        
    def authenticate_user(self, username, password, client_socket_ssl):
        if self.db.authenticate_user(username, password):
            client_socket_ssl.send('User logged in.'.encode('utf-8'))
            self.authenticated_clients[client_socket_ssl] = username
            logging.info('User Logged In: {}'.format(username))
        else:
            client_socket_ssl.send('Invalid username or password.'.encode('utf-8'))
        
                    
if __name__ == '__main__':
    certfile = './certs/server.crt'
    keyfile = './certs/server.key'
    server = ChatServer('localhost', 12100, certfile, keyfile)
    server.start()