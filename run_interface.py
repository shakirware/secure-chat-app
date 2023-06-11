import os
import cherrypy

from client.web_client import WebClient
from common.constants import *

cherrypy.log.access_log.handlers = []
cherrypy.log.error_log.propagate = False
cherrypy.log.access_log.propagate = False

static_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'static'))

cherrypy.config.update({
    'tools.staticdir.on': True,
    'tools.staticdir.dir': static_dir,
})

web_client = WebClient(SERVER_HOST, SERVER_PORT, CERT_FILE)
web_client.start()
cherrypy.quickstart(web_client)
