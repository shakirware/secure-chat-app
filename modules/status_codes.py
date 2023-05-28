class StatusCode:
    INVALID_LOGIN = 1001
    LOGIN_SUCCESSFUL = 1002
    USERNAME_IN_USE = 1003
    INVALID_MESSAGE_FORMAT = 1004 # The message format is invalid. Please ensure the message follows the required format and try again.
    INVALID_MESSAGE_TYPE = 1005 # Invalid message type. Please ensure the message type is valid.
    USERNAME_ALREADY_LOGGED_IN = 1006
    REGISTRATION_SUCCESSFUL = 1007
    USERNAME_ALREADY_EXISTS = 1008