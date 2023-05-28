import cherrypy
import threading
import json
from jinja2 import Environment, FileSystemLoader
from client import ChatClient

access_log = cherrypy.log.access_log
for handler in tuple(access_log.handlers):
    access_log.removeHandler(handler)

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
            else:
                error_message = "Invalid username or password. Please try again."
                template = self.env.get_template('login.html')
                return template.render(error_message=error_message)
        else:
            template = self.env.get_template('login.html')
            return template.render()
    
    @cherrypy.expose
    def chat(self):
        template = self.env.get_template('chat.html')
        return template.render(messages=self.messages)
    
    @cherrypy.expose
    def send_message(self):
        data = json.loads(cherrypy.request.body.read().decode('utf-8'))
        recipient = data.get('recipient')
        message = data.get('message')
    
        if recipient and message:
            self.chat_client.send_message(recipient, message)
            self.messages.append(f'You: {message}')
    
    
    @cherrypy.expose
    @cherrypy.tools.json_out()
    def get_messages(self):
        return self.messages
    
    def update_chat_interface(self, message):
        # Add the message to the array or storage of messages
        self.messages.append(message)

        #if len(self.messages) > MAX_MESSAGES:
        #    self.messages = self.messages[-MAX_MESSAGES:]

    def handle_login_response(self, status_code):
        if status_code == 1002:
            self.login_successful = True
        else:
            self.login_successful = False
        self.login_event.set()

    def run(self):
        cherrypy.quickstart(self)

if __name__ == '__main__':
    cherrypy.log.error_log.propagate = False
    cherrypy.log.access_log.propagate = False

    web_interface = ChatWebInterface()
    
    client = ChatClient('localhost', 12100, './certs/server.crt', web_interface=web_interface)
    client_thread = threading.Thread(target=client.run)
    client_thread.start()
    
    web_interface.set_chat_client(client)
    interface_thread = threading.Thread(target=web_interface.run())
    interface_thread.start()