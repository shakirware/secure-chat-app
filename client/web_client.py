import threading
import cherrypy

from jinja2 import Environment, FileSystemLoader
from client.client_handler import ClientHandler
from client.client import Client

from common.status_codes import LOGIN_SUCCESSFUL


class WebClient(Client):
    """
    A client for the web interface.

    Args:
        host (str): The host address.
        port (int): The port number.
        certfile (str): The path to the certificate file.
        interface (str): The network interface to use.

    Attributes:
        env (jinja2.Environment): The Jinja2 environment for loading templates.
        handler (WebClientHandler): The client handler for handling messages and actions.
        login_event (threading.Event): An event to synchronize login status.
        login_status (bool): The login status of the client.
        messages (list): The list of messages.

    """

    def __init__(self, host, port, certfile, interface=None):
        super().__init__(host, port, certfile, interface)
        self.env = Environment(loader=FileSystemLoader('./client/templates/'))
        self.handler = WebClientHandler(self)
        self.login_event = threading.Event()
        self.login_status = False
        self.messages = None

    @cherrypy.expose
    def index(self, error_message=None):
        """
        The index page handler.

        Args:
            error_message (str): An error message to display (default: None).

        Returns:
            str: The rendered HTML template.

        """
        template = self.env.get_template('login.html')
        return template.render(error_message=error_message)

    @cherrypy.expose
    def login(self, username=None, password=None):
        """
        The login page handler.

        Args:
            username (str): The username (default: None).
            password (str): The password (default: None).

        Returns:
            str: The rendered HTML template.

        """
        if username and password:
            self.handler.handle_login(username, password)
            self.login_event.wait()
            self.login_event.clear()
            self.messages = self.handler.chat_database.get_all_messages()
            if self.login_status:
                raise cherrypy.HTTPRedirect("/chat")
        return self.index(error_message="Invalid username or password. Please try again.") if username and password else self.index()

    @cherrypy.expose
    def chat(self):
        """
        The chat page handler.

        Returns:
            str: The rendered HTML template.

        """
        template = self.env.get_template('chat.html')
        return template.render()

    @cherrypy.expose
    @cherrypy.tools.json_in()
    def send(self, recipient_username=None, message=None):
        """
        Sends an encrypted message.

        Args:
            recipient_username (str): The username of the recipient.
            message (str): The message content.

        """
        data = cherrypy.request.json

        recipient_username = data.get('recipient_username')
        message = data.get('message')

        if recipient_username and message:
            self.handler.send_encrypted_message(message, recipient_username)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    def send_group(self, members=None, message=None):
        """
        Sends an encrypted message.

        Args:
            recipient_username (str): The username of the recipient.
            message (str): The message content.

        """
        data = cherrypy.request.json

        members = data.get('members')
        message = data.get('message')

        if members and message:
            self.handler.send_group_message(message, members)

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def message(self):
        """
        Returns all the messages.

        Returns:
            list: The list of messages.

        """
        messages = {
            'messages': self.handler.chat_database.get_all_messages(),
            'group': self.handler.chat_database.get_all_group_messages()
        
        }
        return messages


class WebClientHandler(ClientHandler):
    """
    A client handler for the web interface.

    Args:
        client (WebClient): The client instance.

    """

    def __init__(self, client):
        super().__init__(client)

    def handle_message_server(self, packet):
        """
        Handles a message from the server.

        Args:
            packet (Packet): The received packet.

        """
        super().handle_message_server(packet)
        self.client.login_status = True if packet.status_code == LOGIN_SUCCESSFUL else self.client.login_status
        self.client.login_event.set()
