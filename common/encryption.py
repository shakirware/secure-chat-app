"""
This module provides cryptographic functions and utilities.

Functions:
    - generate_rsa_keypair(): Generate an RSA key pair.
    - generate_x25519_keypair(): Generate an X25519 key pair.
    - calculate_x25519_shared_secret(private_key, public_key): Calculate the shared secret using X25519 key exchange.
    - encrypt_message_with_aes(message, key): Encrypt a message with AES-256 in CBC mode.
    - decrypt_message_with_aes(encrypted_message, key): Decrypt an AES-256 encrypted message.
    - encrypt_session_token_with_rsa(rsa_public_key, session_token): Encrypt a session token with RSA public key.
    - decrypt_session_token_with_rsa(rsa_private_key, encrypted_token): Decrypt a session token with RSA private key.
    - base64_decode_x25519_public_key(encoded_public_key): Base64 decode an X25519 public key.
    - base64_decode_rsa_public_key(encoded_public_key): Base64 decode an RSA public key.
    - generate_session_token(): Generate a random session token.
    - rsa_public_key_to_base64(rsa_public_key): Convert an RSA public key to base64 encoding.
    - x25519_public_key_to_base64(x25519_public_key): Convert an X25519 public key to base64 encoding.
    - rsa_public_key_to_pem(rsa_public_key): Convert an RSA public key to PEM format.
    - pem_to_rsa_public_key(pem_rsa_public_key): Convert a PEM RSA public key to RSAPublicKey object.
    - calculate_message_key(key): Calculate a 32-byte message key from a key.
"""

import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_rsa_keypair():
    """
    Generate an RSA key pair.

    Returns:
        tuple: A tuple containing the private key and the public key.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key


def generate_x25519_keypair():
    """
    Generate an X25519 key pair.

    Returns:
        tuple: A tuple containing the private key and the public key.
    """
    private_key = X25519PrivateKey.generate()
    return private_key, private_key.public_key()


def calculate_x25519_shared_secret(private_key, public_key):
    """
    Calculate the shared secret using X25519 key exchange.

    Args:
        private_key (X25519PrivateKey): The private key.
        public_key (X25519PublicKey): The public key.

    Returns:
        bytes: The shared secret.
    """
    shared_secret = private_key.exchange(public_key)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=None,
        backend=default_backend()
    )
    return hkdf.derive(shared_secret)


def encrypt_message_with_aes(message, key):
    """
    Encrypt a message with AES-256 in CBC mode.

    Args:
        message (str): The message to encrypt.
        key (bytes): The encryption key.

    Returns:
        str: The base64 encoded encrypted message.
    """
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key),
                    modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = PKCS7(128).padder()
    padded_data = padder.update(
        message.encode()) + padder.finalize()
    encrypted_message = encryptor.update(
        padded_data) + encryptor.finalize()
    encrypted_message_with_iv = iv + encrypted_message
    encrypted_message_b64 = base64.b64encode(
        encrypted_message_with_iv).decode()
    return encrypted_message_b64


def decrypt_message_with_aes(encrypted_message, key):
    """
    Decrypt an AES-256 encrypted message.

    Args:
        encrypted_message (str): The base64 encoded encrypted message.
        key (bytes): The encryption key.

    Returns:
        str: The decrypted message.
    """
    encrypted_message_with_iv = base64.b64decode(encrypted_message)
    iv = encrypted_message_with_iv[:16]
    encrypted_message = encrypted_message_with_iv[16:]
    cipher = Cipher(algorithms.AES(key),
                    modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(
        encrypted_message) + decryptor.finalize()
    unpadder = PKCS7(128).unpadder()
    unpadded_data = unpadder.update(
        decrypted_message) + unpadder.finalize()
    message = unpadded_data.decode()
    return message


def encrypt_session_token_with_rsa(rsa_public_key, session_token):
    """
    Encrypt a session token with RSA public key.

    Args:
        rsa_public_key (RSAPublicKey): The RSA public key.
        session_token (bytes): The session token.

    Returns:
        bytes: The encrypted token.
    """
    return rsa_public_key.encrypt(
        session_token,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def decrypt_session_token_with_rsa(rsa_private_key, encrypted_token):
    """
    Decrypt a session token with RSA private key.

    Args:
        rsa_private_key (RSAPrivateKey): The RSA private key.
        encrypted_token (bytes): The encrypted token.

    Returns:
        bytes: The decrypted token.
    """
    return rsa_private_key.decrypt(
        encrypted_token,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def base64_decode_x25519_public_key(encoded_public_key):
    """
    Base64 decode an X25519 public key.

    Args:
        encoded_public_key (str): The base64 encoded X25519 public key.

    Returns:
        X25519PublicKey: The decoded X25519 public key.
    """
    public_key_bytes = base64.b64decode(encoded_public_key)
    return x25519.X25519PublicKey.from_public_bytes(public_key_bytes)


def base64_decode_rsa_public_key(encoded_public_key):
    """
    Base64 decode an RSA public key.

    Args:
        encoded_public_key (str): The base64 encoded RSA public key.

    Returns:
        RSAPublicKey: The decoded RSA public key.
    """
    public_key_bytes = base64.b64decode(encoded_public_key)
    return load_pem_public_key(public_key_bytes, backend=default_backend())


def generate_session_token():
    """
    Generate a random session token.

    Returns:
        bytes: The base64 encoded session token.
    """
    return Fernet.generate_key()


def rsa_public_key_to_base64(rsa_public_key):
    """
    Convert an RSA public key to base64 encoding.

    Args:
        rsa_public_key (RSAPublicKey): The RSA public key.

    Returns:
        str: The base64 encoded RSA public key.
    """
    public_key_bytes = rsa_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(public_key_bytes).decode('utf-8')


def x25519_public_key_to_base64(x25519_public_key):
    """
    Convert an X25519 public key to base64 encoding.

    Args:
        x25519_public_key (X25519PublicKey): The X25519 public key.

    Returns:
        str: The base64 encoded X25519 public key.
    """
    public_key_bytes = x25519_public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    return base64.b64encode(public_key_bytes).decode('utf-8')


def rsa_public_key_to_pem(rsa_public_key):
    """
    Convert an RSA public key to PEM format.

    Args:
        rsa_public_key (RSAPublicKey): The RSA public key.

    Returns:
        bytes: The PEM formatted RSA public key.
    """
    return rsa_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def pem_to_rsa_public_key(pem_rsa_public_key):
    """
    Convert a PEM RSA public key to RSAPublicKey object.

    Args:
        pem_rsa_public_key (bytes): The PEM formatted RSA public key.

    Returns:
        RSAPublicKey: The RSA public key object.
    """
    rsa_public_key = serialization.load_pem_public_key(
        pem_rsa_public_key,
        backend=default_backend()
    )
    return rsa_public_key


def calculate_message_key(key):
    """
    Calculate a 32-byte message key from a key.

    Args:
        key (bytes): The key.

    Returns:
        bytes: The 32-byte message key.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=None,
        backend=default_backend()
    )
    return hkdf.derive(key)
