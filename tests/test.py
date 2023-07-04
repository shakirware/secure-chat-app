import unittest
import logging
import threading
import warnings
from time import sleep
from server.server import Server
from client.client import Client
from client.client_handler import ClientHandler
from common.status_codes import LOGIN_SUCCESSFUL, INVALID_LOGIN

SERVER_HOST = 'localhost'
SERVER_PORT = 12012
CERT_FILE = './tests/server.crt'
KEY_FILE = './tests/server.key'


class TestServer(Server):
    def __init__(self, host, port, certfile, keyfile):
        super().__init__(host, port, certfile, keyfile)
        self.stop_event = threading.Event()

    def run(self):
        super().run()
        self.stop_event.set()


class TestClient(Client):
    def __init__(self, host, port, certfile, interface=None):
        super().__init__(host, port, certfile, interface)
        self.stop_event = threading.Event()
        self.message_server_event = threading.Event()
        self.handler = TestClientHandler(self)
        self.login_successful = None

    def run(self):
        super().run()
        self.stop_event.set()


class TestClientHandler(ClientHandler):
    def __init__(self, client):
        super().__init__(client)

    def handle_message_server(self, packet):
        super().handle_message_server(packet)
        if packet.status_code == LOGIN_SUCCESSFUL:
            self.client.login_successful = True
        elif packet.status_code == INVALID_LOGIN:
            self.client.login_successful = False

        self.client.message_server_event.set()

    def handle_message_group(self, packet):
        super().handle_message_server(packet)

class TestChat(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        warnings.filterwarnings(action="ignore", message="unclosed", category=ResourceWarning)
        logging.disable(logging.CRITICAL)

    def setUp(self):
        self.server = TestServer(SERVER_HOST, SERVER_PORT, CERT_FILE, KEY_FILE)
        self.server.start()

        self.client = TestClient(SERVER_HOST, SERVER_PORT, CERT_FILE)
        self.client.start()

    def tearDown(self):
        self.client.stop()
        self.server.stop()

        self.client.stop_event.wait()
        self.server.stop_event.wait()

    def test_client_login_success(self):
        self.client.handler.handle_login('shakir', 'test')
        self.client.message_server_event.wait()
        self.assertEqual(self.client.login_successful, True)

    def test_client_login_fail(self):
        self.client.handler.handle_login('bobby', 'test')
        self.client.message_server_event.wait()
        self.assertEqual(self.client.login_successful, False)

if __name__ == '__main__':
    unittest.main()
