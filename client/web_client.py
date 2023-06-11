import threading
import cherrypy

from jinja2 import Environment, FileSystemLoader
from client.client_handler import ClientHandler
from client.client import Client

from common.status_codes import LOGIN_SUCCESSFUL

class WebClient(Client):
    def __init__(self, host, port, certfile, interface=None):
        super().__init__(host, port, certfile, interface)
        self.env = Environment(loader=FileSystemLoader('templates'))
        self.handler = WebClientHandler(self)
        self.login_event = threading.Event()
        self.login_status = False
        self.messages = None
  
    @cherrypy.expose
    def index(self, error_message=None):
        template = self.env.get_template('login.html')
        return template.render(error_message=error_message)

    @cherrypy.expose
    def login(self, username=None, password=None):
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
        template = self.env.get_template('chat.html')
        return template.render()

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def message(self):
        return self.handler.chat_database.get_all_messages()


class WebClientHandler(ClientHandler):
    def __init__(self, client):
        super().__init__(client)

    def handle_message_server(self, packet):
        super().handle_message_server(packet) 
        self.client.login_status = True if packet.status_code == LOGIN_SUCCESSFUL else self.client.login_status
        self.client.login_event.set()
        
    def handle_message_user(self, packet):
        super().handle_message_user(packet)   