import threading
import socket
import ssl

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
        
    def run(self):
        while True:
            client_socket_ssl, client_address = self.server_socket_ssl.accept()
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket_ssl,))
            client_thread.start()
            self.clients.append(client_socket_ssl)
            
    def handle_client(self, client_socket_ssl):
        while True:
            try:
                message = client_socket_ssl.recv(1024).decode('utf-8')
                self.broadcast(message, client_socket_ssl)
            except:
                self.clients.remove(client_socket_ssl)
                break
                
    def broadcast(self, message, client_socket_ssl):
        for client in self.clients:
            if client != client_socket_ssl:
                try:
                    client.send(message.encode('utf-8'))
                except:
                    self.clients.remove(client)
                    
if __name__ == '__main__':
    certfile = './certs/server.crt'
    keyfile = './certs/server.key'
    server = ChatServer('localhost', 12100, certfile, keyfile)
    server.start()