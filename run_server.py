import logging
import sys
import server
from common.constants import *

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s [%(levelname)s] %(message)s')

server = server.Server(SERVER_HOST, SERVER_PORT, CERT_FILE, KEY_FILE)

try:
    server.start()
    while server.is_alive():
        server.join(1)
except KeyboardInterrupt:
    logging.info('Received keyboard interrupt, quitting threads.')
    sys.exit()
