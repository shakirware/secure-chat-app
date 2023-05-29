# maybe a class store keys
import base64
import json
import logging
import os
import socket
import ssl
import sys
import threading
import time

from queue import Queue, Empty
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.padding import PKCS7

from modules.rsa_key_generator import generate_rsa_key_pair
from modules.status_codes import StatusCode
from modules.x25519_key_exchange import generate_key_pair, derive_encryption_key
from config.server_config import *

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s [%(levelname)s] %(message)s')

class ChatClient:
    def __init__(self, host, port, cert_file, web_interface=None):
        self.host = host
        self.port = port
        self.cert_file = cert_file
        self.x25519_private_key, self.x25519_public_key = generate_key_pair()
        self.rsa_private_key, self.rsa_public_key = generate_rsa_key_pair()
        self.shared_public_keys = {}
        self.message_keys = {}
        self.message_queue = Queue()
        self.socket = None
        self.token = None
        self.context = None
        self.username = None
        self.is_running = True
        self.web_interface = web_interface

    def connect(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.context.load_verify_locations(self.cert_file)
        self.socket = self.context.wrap_socket(
            self.socket, server_hostname=self.host)
        self.socket.connect((self.host, self.port))

    def send_message(self, recipient_username, message):
        if recipient_username not in self.shared_public_keys:
            logging.info(
                "Unable to retrieve the public key for the user %s.", recipient_username)
            return

        message_key = self.generate_message_key(recipient_username)

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(message_key),
                        modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        padder = PKCS7(128).padder()
        padded_data = padder.update(
            message.encode('utf-8')) + padder.finalize()

        encrypted_message = encryptor.update(
            padded_data) + encryptor.finalize()
        encrypted_message_with_iv = iv + encrypted_message

        encrypted_message_b64 = base64.b64encode(
            encrypted_message_with_iv).decode('utf-8')

        token_b64 = base64.b64encode(self.token).decode('utf-8')

        data = {
            'type': 'message',
            'sender': self.username,
            'recipient': recipient_username,
            'message': encrypted_message_b64,
            'token': token_b64,
            'timestamp': int(time.time())
        }
        json_message = json.dumps(data)
        self.message_queue.put(json_message)
        logging.info('You: %s', message)

    def generate_message_key(self, username):
        if username not in self.message_keys:
            key = derive_encryption_key(
                self.x25519_private_key, self.shared_public_keys[username])
            logging.info("DH Shared Secret = %s.", key.hex())
        else:
            key = self.message_keys[username]

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=None,
            backend=default_backend()
        )
        new_key = hkdf.derive(key)
        logging.info("Message key = %s.", new_key.hex())
        self.message_keys[username] = new_key
        return new_key

    def send_x25519_public_key(self):
        public_key_raw = self.x25519_public_key.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        public_key_b64 = base64.b64encode(public_key_raw).decode('utf-8')
        data = {
            'type': 'public_key_x25519',
            'public_key': public_key_b64
        }
        json_message = json.dumps(data)
        self.message_queue.put(json_message)

    def send_rsa_public_key(self):
        public_key_bytes = self.rsa_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_key_b64 = base64.b64encode(public_key_bytes).decode('utf-8')
        data = {
            'type': 'public_key_rsa',
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

                data = json.loads(message)

                message_type = data.get('type')
                message_handlers = {
                    'public_key': self.handle_public_key,
                    'message': self.handle_message_user,
                    'server': self.handle_message_server,
                    'token': self.handle_token
                }

                handler = message_handlers.get(message_type)

                if handler:
                    handler(data)
                else:
                    logging.info('Received message: %s', data)

            except socket.error as error:
                logging.error(
                    'Error occurred while receiving messages: %s', error)
                break

    def handle_token(self, data):
        encrypted_token_b64 = data.get('token')
        encrypted_token = base64.b64decode(encrypted_token_b64)
        decrypted_token = self.rsa_private_key.decrypt(
            encrypted_token,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            ))
        self.token = decrypted_token
        logging.info('Token received from server: %s', decrypted_token)

    def handle_message_server(self, data):
        message = data.get('message')
        status_code = data.get('status_code')

        if status_code is None:
            logging.info('SERVER: %s', message)
            return

        if self.web_interface:
            self.web_interface.handle_status_response(data, status_code)

        if status_code in (StatusCode.INVALID_LOGIN, StatusCode.LOGIN_SUCCESSFUL):
            if status_code == StatusCode.LOGIN_SUCCESSFUL:
                logging.info('SERVER %s: Logged in successfully.', status_code)
        elif status_code == StatusCode.USER_LOGGED_OUT:
            username = message
            if self.message_keys.get(username):
                del self.message_keys[username]
            logging.info("SERVER %s: User '%s' logged out. Message Keys for %s deleted.",
                         status_code, username, username)
        elif status_code == StatusCode.USER_LOGGED_IN:
            username = message
            logging.info("SERVER %s: User '%s' logged in.",
                         status_code, username)
        else:
            logging.info('SERVER: Status Code %s', status_code)

    def handle_message_user(self, data):
        sender = data.get('sender')
        message_b64 = data.get('message')

        encrypted_message_with_iv = base64.b64decode(message_b64)
        iv = encrypted_message_with_iv[:16]
        encrypted_message = encrypted_message_with_iv[16:]

        message_key = self.generate_message_key(sender)

        cipher = Cipher(algorithms.AES(message_key),
                        modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_message = decryptor.update(
            encrypted_message) + decryptor.finalize()

        unpadder = PKCS7(128).unpadder()
        unpadded_data = unpadder.update(
            decrypted_message) + unpadder.finalize()
        message = unpadded_data.decode('utf-8')

        if self.web_interface:
            data_copy = data.copy()
            data_copy['message'] = message
            self.web_interface.update_chat_interface(data_copy)

        logging.info('%s: %s', sender, message)

    def handle_public_key(self, data):
        public_key_b64 = data['public_key']
        public_key_bytes = base64.b64decode(public_key_b64)
        public_key = x25519.X25519PublicKey.from_public_bytes(public_key_bytes)
        owner = data.get('owner')
        self.shared_public_keys[owner] = public_key
        logging.info(
            'The public key provided by user %s has been successfully received and stored.', owner)

    def send_messages(self):
        while self.is_running:
            try:
                json_message = self.message_queue.get(timeout=1)
                self.socket.send(json_message.encode())
                self.message_queue.task_done()
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

        self.send_x25519_public_key()
        self.send_rsa_public_key()

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
    client = ChatClient(SERVER_HOST, SERVER_PORT, CERT_FILE)
    client.run()
