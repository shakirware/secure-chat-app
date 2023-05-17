import socket
import ssl
import threading
import base64
import json
import time
import logging
import sys

from queue import Queue, Empty
from cryptography.hazmat.primitives import serialization
from x25519_key_exchange import generate_key_pair, derive_encryption_key
from cryptography.hazmat.primitives.asymmetric import x25519

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
CERT_FILE = './certs/server.crt'

class ChatClient:
    def __init__(self, host, port, cert_file):
        self.host = host
        self.port = port
        self.cert_file = cert_file
        self.private_key, self.public_key = generate_key_pair()
        self.shared_public_keys = {}
        self.message_queue = Queue()
        self.socket = None
        self.context = None
        self.username = None
        self.is_running = True

    def connect(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.context.load_verify_locations(self.cert_file)
        self.socket = self.context.wrap_socket(
            self.socket, server_hostname=self.host)
        self.socket.connect((self.host, self.port))

    def send_message(self, recipient_username, message):
        shared_key = derive_encryption_key(self.private_key, self.shared_public_keys[recipient_username])
        logging.info(f"Shared key = {shared_key.hex()}")
        
        data = {
            'type': 'message',
            'sender': self.username,
            'recipient': recipient_username,
            'message': base64.b64encode(message.encode('utf-8')).decode('utf-8'),
            'timestamp': int(time.time())
        }
        json_message = json.dumps(data)
        self.message_queue.put(json_message)

    def send_public_key(self):
        public_key_raw = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        public_key_b64 = base64.b64encode(public_key_raw).decode('utf-8')
        data = {
            'type': 'public_key',
            'public_key': public_key_b64
        }
        json_message = json.dumps(data)
        self.message_queue.put(json_message)

    def send_login_request(self, username, password):
        data = {
            'type': 'login',
            'username': username,
            'password': password
        }
        json_message = json.dumps(data)
        self.message_queue.put(json_message)

    def send_register_request(self, username, password):
        data = {
            'type': 'register',
            'username': username,
            'password': password
        }
        json_message = json.dumps(data)
        self.message_queue.put(json_message)

    def receive_messages(self):
        while self.is_running:
            try:
                message = self.socket.recv(1024).decode()
                if not message:
                    break
                logging.info('Received message: %s', message)
                
                data = json.loads(message)
                if data['type'] == 'public_key':
                    self.handle_public_key(data)
                    
            except socket.error as error:
                logging.error(
                    'Error occurred while receiving messages: %s', error)
                break
                
    def handle_public_key(self, data):
        public_key_b64 = data['public_key']
        public_key_bytes = base64.b64decode(public_key_b64)
        public_key = x25519.X25519PublicKey.from_public_bytes(public_key_bytes)
        owner = data.get('owner')
        self.shared_public_keys[owner] = public_key

    def send_messages(self):
        while self.is_running:
            try:
                json_message = self.message_queue.get(timeout=1)
                self.socket.send(json_message.encode())
                self.message_queue.task_done()
                logging.info('Sent message: %s', json_message)
            except socket.error as error:
                logging.error(
                    'Error occurred while receiving messages: %s', error)
                break
            except Empty:
                continue

    def handle_user_input(self):
        commands = {
            "/quit": self.quit,
            "/msg": self.send_message,
            "/login": self.send_login_request,
            "/register": self.send_register_request
        }
        try:
            while self.is_running:
                input_str = input()
                command, *args = input_str.split()
                
                if command.lower() == "/msg" and len(args) >= 2:
                    recipient = args[0]
                    message = " ".join(args[1:])
                    self.send_message(recipient, message)
                elif command.lower() in commands:
                    commands[command.lower()](*args)
                else:
                    logging.info("Invalid Command.")
        except KeyboardInterrupt:
            logging.info("Keyboard interrupt received. Shutting down server.")
            self.quit()

    def quit(self):
        self.is_running = False
        self.socket.close()

    def run(self):
        self.connect()
        logging.info("Connected to server")

        self.send_public_key()

        receive_thread = threading.Thread(target=self.receive_messages)
        receive_thread.start()

        send_thread = threading.Thread(target=self.send_messages)
        send_thread.start()

        self.handle_user_input()

        self.message_queue.join()
        receive_thread.join()
        send_thread.join()
        sys.exit(0)


if __name__ == '__main__':
    client = ChatClient('localhost', 12100, CERT_FILE)
    client.run()