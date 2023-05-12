import socket
import threading 

class ChatClient:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    def connect(self):
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
        
        username = input("Enter username: ")
        self.send_message(f"{username} has joined the chat")
        
        receive_thread = threading.Thread(target=self.receive_messages)
        receive_thread.start()
        
        while True:
            message = input()
            if message.lower() == "quit":
                self.send_message(f"{username} has left the chat")
                self.socket.close()
                break
            else:
                self.send_message(f"{username}: {message}")
                
if __name__ == '__main__':
    client = ChatClient('localhost', 12100)
    client.run()