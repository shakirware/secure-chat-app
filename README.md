# secure-chat-app

**secure-chat-app** is an end-to-end encrypted chat application designed to ensure secure communication between users. It employs various cryptographic techniques such as x25519 Diffie-Hellman key exchange, AES encryption, ratchet functions, and session tokens encrypted with long-term RSA keys. The application utilizes an SQLite server database to store user information securely, employing hashing and salting for enhanced security. Each client also maintains its own local database to store chat conversations. The project includes both a command-line interface and a graphical web interface built using CherryPy.

## Features

- **End-to-End Encryption:** All messages exchanged between users are encrypted using AES encryption, providing a high level of confidentiality.
- **x25519 Diffie-Hellman Key Exchange:** Secure shared secrets are established between users using the x25519 Diffie-Hellman key exchange algorithm, ensuring that only intended recipients can decrypt messages.
- **Ratchet Functions:** The application utilizes ratchet functions to provide forward secrecy, generating new keys for each session to prevent compromise of previous sessions.
- **Session Tokens:** Session tokens are generated using long-term RSA keys and encrypted to maintain the security of each session.
- **SQLite Server Database:** User information is securely stored in an SQLite server database. The database implements hashing and salting techniques to protect user credentials.
- **Client Databases:** Each client maintains its own local database to store chat conversations securely.
- **Command-Line Interface:** The project provides a command-line interface (CLI) that allows users to interact with the chat application via a text-based interface.
- **Graphical Web Interface:** The project also includes a graphical web interface built using CherryPy, offering a user-friendly way to access and use the chat application.

![main_page](https://github.com/shakirware/secure-chat-app/assets/25272123/a49af094-3e90-4b90-a4c1-c385fa4b0575)
![server_command_interface_1](https://github.com/shakirware/secure-chat-app/assets/25272123/906e2b61-d1c6-4067-bf51-fab9dd503099)
![testing_4](https://github.com/shakirware/secure-chat-app/assets/25272123/69e96ec3-ccb7-43b0-ae4a-12bf0d699e8e)


## License

[MIT License](https://opensource.org/licenses/MIT)
