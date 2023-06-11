"""
This module provides functions for sending various types of responses to clients.

Module dependencies:
    - time: Provides time-related functions.
    - common.status_codes: Provides constants for status codes.
    - common.packet: Provides the Packet class for constructing response packets.

Functions:
    - send_login_fail_response(socket, received_packet): Sends a login fail response to the client.
    - send_login_success_response(socket, received_packet): Sends a login success response to the client.
    - send_registration_success_response(socket, received_packet): Sends a registration success response to the client.
    - send_username_already_exists_response(socket, received_packet): Sends a username already exists response to the client.
    - send_weak_credentials_response(socket, received_packet): Sends a weak credentials response to the client.
    - send_user_logged_out_response(socket, username): Sends a user logged out response to the client.
    - send_user_logged_in_response(socket, username): Sends a user logged in response to the client.
    - send_invalid_message_type_response(socket): Sends an invalid message type response to the client.
    - send_rsa_public_key_stored(socket): Sends an RSA public key stored response to the client.
    - send_rsa_public_key_not_stored(socket): Sends an RSA public key not stored response to the client.
    - send_user_already_logged_in(socket): Sends a user already logged in response to the client.
    - send_x25519_public_key(socket, public_key, owner): Sends an X25519 public key to the client.
    - send_token(socket, token): Sends a session token to the client.
    - send_undelivered_message(socket, packet): Sends an undelivered message response to the client.
"""

import time
from common.status_codes import *
from common.packet import Packet


def send_login_fail_response(socket, received_packet):
    """
    Sends a login fail response to the client.

    Args:
        socket (socket): The client socket to send the response to.
        received_packet (Packet): The received packet from the client.
    """
    packet = Packet(
        'server',
        username=received_packet.username,
        status_code=INVALID_LOGIN,
        timestamp=int(time.time())
    )
    json_data = packet.to_json()
    socket.send(json_data.encode('utf-8'))


def send_login_success_response(socket, received_packet):
    """
    Sends a login success response to the client.

    Args:
        socket (socket): The client socket to send the response to.
        received_packet (Packet): The received packet from the client.
    """
    packet = Packet(
        'server',
        username=received_packet.username,
        status_code=LOGIN_SUCCESSFUL,
        timestamp=int(time.time())
    )
    json_data = packet.to_json()
    socket.send(json_data.encode('utf-8'))


def send_registration_success_response(socket, received_packet):
    """
    Sends a registration success response to the client.

    Args:
        socket (socket): The client socket to send the response to.
        received_packet (Packet): The received packet from the client.
    """
    packet = Packet(
        'server',
        username=received_packet.username,
        status_code=REGISTRATION_SUCCESSFUL,
        timestamp=int(time.time())
    )
    json_data = packet.to_json()
    socket.send(json_data.encode('utf-8'))


def send_username_already_exists_response(socket, received_packet):
    """
    Sends a username already exists response to the client.

    Args:
        socket (socket): The client socket to send the response to.
        received_packet (Packet): The received packet from the client.
    """
    packet = Packet(
        'server',
        username=received_packet.username,
        status_code=USERNAME_ALREADY_EXISTS,
        timestamp=int(time.time())
    )
    json_data = packet.to_json()
    socket.send(json_data.encode('utf-8'))


def send_weak_credentials_response(socket, received_packet):
    """
    Sends a weak credentials response to the client.

    Args:
        socket (socket): The client socket to send the response to.
        received_packet (Packet): The received packet from the client.
    """
    packet = Packet(
        'server',
        username=received_packet.username,
        status_code=WEAK_CREDENTIALS,
        timestamp=int(time.time())
    )
    json_data = packet.to_json()
    socket.send(json_data.encode('utf-8'))


def send_user_logged_out_response(socket, username):
    """
    Sends a user logged out response to the client.

    Args:
        socket (socket): The client socket to send the response to.
        username (str): The username of the logged out user.
    """
    packet = Packet(
        'server',
        username=username,
        status_code=USER_LOGGED_OUT,
        timestamp=int(time.time())
    )
    json_data = packet.to_json()
    socket.send(json_data.encode('utf-8'))


def send_user_logged_in_response(socket, username):
    """
    Sends a user logged in response to the client.

    Args:
        socket (socket): The client socket to send the response to.
        username (str): The username of the logged in user.
    """
    packet = Packet(
        'server',
        username=username,
        status_code=USER_LOGGED_IN,
        timestamp=int(time.time())
    )
    json_data = packet.to_json()
    socket.send(json_data.encode('utf-8'))


def send_invalid_message_type_response(socket):
    """
    Sends an invalid message type response to the client.

    Args:
        socket (socket): The client socket to send the response to.
    """
    packet = Packet(
        'server',
        status_code=INVALID_MESSAGE_TYPE,
        timestamp=int(time.time())
    )
    json_data = packet.to_json()
    socket.send(json_data.encode('utf-8'))


def send_rsa_public_key_stored(socket):
    """
    Sends an RSA public key stored response to the client.

    Args:
        socket (socket): The client socket to send the response to.
    """
    packet = Packet(
        'server',
        status_code=RSA_PUBLIC_KEY_STORED,
        timestamp=int(time.time())
    )
    json_data = packet.to_json()
    socket.send(json_data.encode('utf-8'))


def send_rsa_public_key_not_stored(socket):
    """
    Sends an RSA public key not stored response to the client.

    Args:
        socket (socket): The client socket to send the response to.
    """
    packet = Packet(
        'server',
        status_code=RSA_PUBLIC_KEY_NOT_STORED,
        timestamp=int(time.time())
    )
    json_data = packet.to_json()
    socket.send(json_data.encode('utf-8'))


def send_user_already_logged_in(socket):
    """
    Sends a user already logged in response to the client.

    Args:
        socket (socket): The client socket to send the response to.
    """
    packet = Packet(
        'server',
        status_code=USERNAME_ALREADY_LOGGED_IN,
        timestamp=int(time.time())
    )
    json_data = packet.to_json()
    socket.send(json_data.encode('utf-8'))


def send_x25519_public_key(socket, public_key, owner):
    """
    Sends an X25519 public key to the client.

    Args:
        socket (socket): The client socket to send the response to.
        public_key (str): The X25519 public key.
        owner (str): The owner of the public key.
    """
    packet = Packet(
        'public_key',
        owner=owner,
        public_key=public_key,
        timestamp=int(time.time())
    )
    json_data = packet.to_json()
    socket.send(json_data.encode('utf-8'))


def send_token(socket, token):
    """
    Sends a session token to the client.

    Args:
        socket (socket): The client socket to send the response to.
        token (str): The session token.
    """
    packet = Packet(
        'token',
        token=token,
        timestamp=int(time.time())
    )
    json_data = packet.to_json()
    socket.send(json_data.encode('utf-8'))


def send_undelivered_message(socket, packet):
    """
    Sends an undelivered message response to the client.

    This function is used to send a response to the client indicating that a message was not delivered.
    It sets the packet type to 'offline', converts the packet to JSON format, and sends it to the client socket.

    Args:
        socket (socket): The client socket to send the response to.
        packet (Packet): The packet containing the undelivered message.

    Returns:
        None
    """
    packet.packet_type = 'offline'
    json_data = packet.to_json()
    socket.send(json_data.encode('utf-8'))
