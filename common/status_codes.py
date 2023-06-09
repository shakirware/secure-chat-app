"""
This module defines the status codes used in the application.

Status codes are numeric values that represent different states or outcomes
in the application's logic. They provide a standardized way of indicating
the result or status of an operation.

Status Codes:
    INVALID_LOGIN (int): The login credentials provided are invalid.
    LOGIN_SUCCESSFUL (int): The login was successful.
    USERNAME_IN_USE (int): The username is already in use.
    INVALID_MESSAGE_FORMAT (int): The message format is invalid.
    INVALID_MESSAGE_TYPE (int): The message type is invalid.
    USERNAME_ALREADY_LOGGED_IN (int): The username is already logged in.
    REGISTRATION_SUCCESSFUL (int): The registration was successful.
    USERNAME_ALREADY_EXISTS (int): The username already exists.
    USER_LOGGED_OUT (int): The user has been logged out.
    USER_LOGGED_IN (int): The user has been logged in.
    WEAK_CREDENTIALS (int): The provided credentials are weak.
    RSA_PUBLIC_KEY_STORED (int): The RSA public key has been stored.
    RSA_PUBLIC_KEY_NOT_STORED (int): The RSA public key has not been stored.
"""

INVALID_LOGIN = 1001
LOGIN_SUCCESSFUL = 1002
USERNAME_IN_USE = 1003
INVALID_MESSAGE_FORMAT = 1004
INVALID_MESSAGE_TYPE = 1005
USERNAME_ALREADY_LOGGED_IN = 1006
REGISTRATION_SUCCESSFUL = 1007
USERNAME_ALREADY_EXISTS = 1008
USER_LOGGED_OUT = 1009
USER_LOGGED_IN = 1010
WEAK_CREDENTIALS = 1011
RSA_PUBLIC_KEY_STORED = 1012
RSA_PUBLIC_KEY_NOT_STORED = 1013
