import socket
import ssl
import threading

class ChatClient:
    def __init__(self, host, port, certfile):
        self.host = host
        self.port = port
        self.certfile = certfile
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.context.load_verify_locations(self.certfile) # path to server's certificate
        
    def connect(self):
        self.socket = self.context.wrap_socket(self.socket, server_hostname=self.host)
        self.socket.connect((self.host, self.port))
        
    def send_message(self, message):
        self.socket.send(message.encode())
        
    def receive_messages(self):
        while True:
            message = self.socket.recv(1024).decode()
            if not message:
                break
            print(message)
        
    def run(self):
        self.connect()
        print("Connected to server")
        
        
        receive_thread = threading.Thread(target=self.receive_messages)
        receive_thread.start()
        
        while True:
            message = input()
            if message.lower() == "quit":
                self.socket.close()
                break
            else:
                self.send_message(f"{message}")
                
if __name__ == '__main__':
    certfile = './certs/server.crt'
    client = ChatClient('localhost', 12100, certfile)
    client.run()