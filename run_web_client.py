import os
import cherrypy
import client

from common.constants import *

cherrypy.log.access_log.handlers = []
cherrypy.log.error_log.propagate = False
cherrypy.log.access_log.propagate = False

static_dir = os.path.abspath(os.path.join(
    os.path.dirname(__file__), './client/static/'))

cherrypy.config.update({
    'tools.staticdir.on': True,
    'tools.staticdir.dir': static_dir,
})

web_client = client.WebClient(SERVER_HOST, SERVER_PORT, CERT_FILE)
web_client.start()
cherrypy.quickstart(web_client)
