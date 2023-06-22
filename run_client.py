import logging
import sys
import client
from common.constants import *
"""
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s [%(levelname)s] %(message)s')

client = client.Client(SERVER_HOST, SERVER_PORT, CERT_FILE)

try:
    client.start()
    while client.is_alive():
        client.join(1)
except KeyboardInterrupt:
    logging.info('Received keyboard interrupt, quitting threads.')
    sys.exit()
"""

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s [%(levelname)s] %(message)s')

client = client.Client(SERVER_HOST, SERVER_PORT, CERT_FILE)
client.start()

try:
    while True:
        pass
except KeyboardInterrupt:
    logging.info('Received keyboard interrupt, quitting threads.')
    client.stop()