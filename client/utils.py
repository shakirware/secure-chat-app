"""
This module provides functions for generating, saving, and loading RSA key pairs and handling RSA public keys.

Module dependencies:
    - os: Provides functions for interacting with the operating system.
    - base64: Provides functions for encoding and decoding data using Base64.
    - cryptography.hazmat.primitives.serialization: Provides functions for serializing and deserializing cryptographic objects.
    - common.encryption: Provides the generate_rsa_keypair function for generating RSA key pairs.
    - common.packet: Provides the Packet class for constructing packets.

Functions:
    - generate_rsa_key: Generates an RSA key pair for a given username and saves the private and public keys to files.
    - save_private_key: Saves the RSA private key to a file.
    - save_public_key: Saves the RSA public key to a file.
    - generate_and_send_rsa_public_key: Generates and sends the RSA public key for a given username.
    - load_rsa_private_key: Loads the RSA private key from a file.
    - load_rsa_public_key: Loads the RSA public key from a file.
"""

import os
import base64

from cryptography.hazmat.primitives import serialization

from common.encryption import generate_rsa_keypair, rsa_public_key_to_base64
from common.packet import Packet


def generate_rsa_key(username):
    """
    Generates an RSA key pair for the specified username and saves the private and public keys to files.

    Args:
        username (str): The username for which to generate the RSA key pair.

    Returns:
        cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey: The generated RSA public key.
    """
    rsa_private_key, rsa_public_key = generate_rsa_keypair()

    user_folder = f"./storage/{username}"
    if not os.path.exists(user_folder):
        os.makedirs(user_folder)

    private_key_file = os.path.join(user_folder, "rsa_private_key.pem")
    public_key_file = os.path.join(user_folder, "rsa_public_key.pem")

    save_private_key(private_key_file, rsa_private_key)
    save_public_key(public_key_file, rsa_public_key)

    return rsa_public_key


def save_private_key(file_path, rsa_private_key):
    """
    Saves the RSA private key to a file.

    Args:
        file_path (str): The path of the file to save the private key to.
        rsa_private_key (cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey): The RSA private key.
    """
    with open(file_path, "wb") as file_:
        private_key_bytes = rsa_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        file_.write(private_key_bytes)


def save_public_key(file_path, rsa_public_key):
    """
    Saves the RSA public key to a file.

    Args:
        file_path (str): The path of the file to save the public key to.
        rsa_public_key (cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey): The RSA public key.
    """
    with open(file_path, "wb") as file_:
        public_key_bytes = rsa_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        file_.write(public_key_bytes)


def generate_and_send_rsa_public_key(username, message_queue):
    """
    Generates the RSA public key for a given username and sends it as a packet.

    Args:
        username (str): The username for which to generate the RSA public key.
        message_queue (Queue): The message queue to put the generated packet in.
    """
    rsa_public_key = generate_rsa_key(username)
    rsa_public_key_b64 = rsa_public_key_to_base64(rsa_public_key)
    packet = Packet('public_key_rsa', username=username,
                    public_key=rsa_public_key_b64)
    message_queue.put(packet)


def load_rsa_private_key(private_key_path):
    """
    Loads the RSA private key from a file.

    Args:
        private_key_path (str): The path of the file containing the RSA private key.

    Returns:
        cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey: The loaded RSA private key.
    """
    with open(private_key_path, "rb") as private_key_file:
        private_key = serialization.load_pem_private_key(
            private_key_file.read(), password=None)
    return private_key


def load_rsa_public_key(public_key_path):
    """
    Loads the RSA public key from a file.

    Args:
        public_key_path (str): The path of the file containing the RSA public key.

    Returns:
        cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey: The loaded RSA public key.
    """
    with open(public_key_path, "rb") as public_key_file:
        public_key = serialization.load_pem_public_key(public_key_file.read())
    return public_key
