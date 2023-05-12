import threading
import socket

class ChatServer(threading.Thread):
    def __init__(self, host, port):
        super().__init__()
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.clients = []
        
    def run(self):
        while True:
            client_socket, client_address = self.server_socket.accept()
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_thread.start()
            self.clients.append(client_socket)
            
    def handle_client(self, client_socket):
        while True:
            try:
                message = client_socket.recv(1024).decode('utf-8')
                self.broadcast(message, client_socket)
            except:
                self.clients.remove(client_socket)
                break
                
    def broadcast(self, message, client_socket):
        for client in self.clients:
            if client != client_socket:
                try:
                    client.send(message.encode('utf-8'))
                except:
                    self.clients.remove(client)
                    
if __name__ == '__main__':
    server = ChatServer('localhost', 12100)
    server.start()