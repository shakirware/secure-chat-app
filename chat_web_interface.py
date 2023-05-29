import threading
import os
import time
import cherrypy

from jinja2 import Environment, FileSystemLoader

from client import ChatClient
from modules.status_codes import StatusCode
from config.server_config import *

# static directory
static_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'static'))

cherrypy.config.update({
    'tools.staticdir.on': True,
    'tools.staticdir.dir': static_dir,
})

access_log = cherrypy.log.access_log
access_log.handlers = []


class ChatWebInterface:
    def __init__(self):
        self.chat_client = None
        self.env = Environment(loader=FileSystemLoader('templates'))
        self.login_event = threading.Event()
        self.login_successful = False
        self.messages = []

    def set_chat_client(self, chat_client):
        self.chat_client = chat_client

    @cherrypy.expose
    def index(self):
        raise cherrypy.HTTPRedirect("/login")

    @cherrypy.expose
    def login(self, username=None, password=None):
        if username and password:
            self.chat_client.send_login_request(username, password)
            self.login_event.wait()
            self.login_event.clear()
            if self.login_successful:
                raise cherrypy.HTTPRedirect("/chat")
            error_message = "Invalid username or password. Please try again."
        else:
            error_message = None

        template = self.env.get_template('login.html')
        return template.render(error_message=error_message)

    @cherrypy.expose
    def chat(self):
        template = self.env.get_template('chat.html')
        return template.render(messages=self.messages)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    def send_message(self):
        data = cherrypy.request.json
        recipient = data.get('recipient')
        message = data.get('message')

        if recipient and message:
            self.chat_client.send_message(recipient, message)
            data = {
                'sender': 'You',
                'message': message,
                'timestamp': int(time.time())
            }
            self.messages.append(data)

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def get_messages(self):
        return self.messages

    def update_chat_interface(self, message):
        # Add the message to the array or storage of messages
        self.messages.append(message)

    def handle_status_response(self, data, status_code):
        actions = {
            StatusCode.LOGIN_SUCCESSFUL: lambda: setattr(self, 'login_successful', True),
            StatusCode.INVALID_LOGIN: lambda: setattr(self, 'login_successful', False),
            StatusCode.USER_LOGGED_IN: lambda: self.add_server_message(
                StatusCode.USER_LOGGED_IN, data),
            StatusCode.USER_LOGGED_OUT: lambda: self.add_server_message(
                StatusCode.USER_LOGGED_OUT, data)
        }

        action = actions.get(status_code)
        if action:
            action()

        self.login_event.set()

    def add_server_message(self, status_code, data):
        message = {
            'sender': f'SERVER {status_code}',
            'message': f'User {data["message"]} logged in.',
            'timestamp': data['timestamp']
        }
        self.messages.append(message)

    def run(self):
        cherrypy.quickstart(self)


if __name__ == '__main__':
    cherrypy.log.error_log.propagate = False
    cherrypy.log.access_log.propagate = False

    web_interface = ChatWebInterface()

    client = ChatClient(SERVER_HOST, SERVER_PORT, CERT_FILE, web_interface=web_interface)
    client_thread = threading.Thread(target=client.run)
    client_thread.start()

    web_interface.set_chat_client(client)
    interface_thread = threading.Thread(target=web_interface.run)
    interface_thread.start()
