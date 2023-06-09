"""
This module provides configurations for the server.

Module dependencies:
    - yaml: Provides functions for working with YAML files.

Configuration Variables:
    - MAX_CLIENTS: Maximum number of clients that can connect to the server.
    - DATABASE_FILE: Path to the database file.
    - CERT_FILE: Path to the certificate file.
    - KEY_FILE: Path to the private key file.
    - SERVER_HOST: Server host address.
    - SERVER_PORT: Server port number.
"""

import yaml

with open('config.yaml', 'r') as file:
    config = yaml.safe_load(file)

MAX_CLIENTS = config['max-clients']
DATABASE_FILE = config['database-file']
CERT_FILE = config['cert-file']
KEY_FILE = config['key-file']
SERVER_HOST = config['server-host']
SERVER_PORT = config['server-port']
