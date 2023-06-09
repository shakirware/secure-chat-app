import logging
import sys

from server.server import Server
from common.constants import *

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s [%(levelname)s] %(message)s')

server = Server(SERVER_HOST, SERVER_PORT, CERT_FILE, KEY_FILE)

try:
    server.start()
    while server.is_alive():
        server.join(1)
except KeyboardInterrupt:
    logging.info('Received keyboard interrupt, quitting threads.')
    sys.exit()
