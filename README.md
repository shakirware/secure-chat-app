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


**Secure Server Infrastructure:**

TLS socket ensures a secure connection between the client and server.

**User Authentication and Encryption:**

RSA Public keys are stored by the server for each user and employed to encrypt tokens.
User registration includes password validation, and the server permanently stores the user's RSA long-term key during registration.
The client's login process involves username and password authentication.

**Key Exchange: **

Elliptic curve Diffie-Hellman key exchange using Curve25519 is employed.
X25519 public keys are exchanged with other users upon logging in, ensuring secure communication.

**Multi-threaded Architecture: **

The client and server operate in a multi-threaded environment, enabling efficient handling of multiple requests simultaneously.

**Command Line Interface (CLI): **

The system offers a command line interface with a range of commands, facilitating user interaction and control.

**Secure Messaging: **

Messages exchanged between users are encrypted using AES-256 encryption algorithm, ensuring confidentiality.
Each message is encrypted with a unique key generated from a HMAC Key Derivation function.

**Offline Message Management:**

The server stores encrypted messages for offline users, ensuring delivery upon re-establishing an online connection.
Users can send messages to offline recipients, ensuring seamless communication.

**Secure Databases:

The system employs SQLite for databases.
User database employs hashing and salting techniques to enhance security.

## License

[MIT License](https://opensource.org/licenses/MIT)
