import unittest
from server.server import Server
from client.client import Client

class LoginTestCase(unittest.TestCase):
    def setUp(self):
        self.server = Server()
        self.server.start()

        self.client = Client()
        self.client.start()

    def tearDown(self):
        self.client.stop()
        self.server.stop()

    def test_login(self):
        username = 'test_user'
        password = 'test_password'

        # Perform login operation
        self.client.handler.handle_login(username, password)

        # Wait for the server to process the login request
        response_packet = self.server.handler.receive_packet()

        # Assert that the login was successful
        self.assertEqual(response_packet.type, 'login_response')
        self.assertTrue(response_packet.success)

if __name__ == '__main__':
    unittest.main()
