# Encrypted Chat

End-to-end encrypted chat system with authentication, multi-client support, and cross-platform compatibility.

## Purpose

This tool is part of my cybersecurity homelab portfolio. It demonstrates:

- End-to-end encryption (AES-128 via Fernet)
- Key derivation (PBKDF2)
- Client-server architecture
- Multi-threading
- Cross-platform communication (WSL + Android)

## Technologies

- Python 3.14+
- Cryptography (Fernet, AES)
- Socket programming
- Threading
- JSON

## Installation

git clone https://github.com/felix-meow/homelab.git
cd homelab/projects/encrypted-chat

pip install -r requirements.txt

## Usage

### Start the server

python3 server.py --host 0.0.0.0 -p 5001 --password chat123

### Connect a client

python3 client.py -s 127.0.0.1 -p 5001 -u Alice --password chat123

### Options

Server:
  --host         Host to bind to (default: 0.0.0.0)
  -p, --port     Port to listen on (default: 5001)
  --password     Server password (default: chat123)

Client:
  -s, --server   Server IP address (default: 127.0.0.1)
  -p, --port     Server port (default: 5001)
  -u, --username Your username
  --password     Server password (default: chat123)

### Client Commands

| Command | Description |
|---------|-------------|
| /quit | Exit the chat |
| /help | Show available commands |
| /clear | Clear the screen |

## Example Session

Server:
[CONNECT] Alice from 127.0.0.1:55256
[ENCRYPTED] from Alice

Client Alice:
[CONNECT] Connected to 127.0.0.1:5001
[AUTH] Successfully authenticated!

[21:00:20] Bob: Salut Alice!

## Security

| Feature | Implementation |
|---------|----------------|
| Encryption | AES-128 (Fernet) |
| Key Derivation | PBKDF2 (100k iterations) |
| Authentication | SHA256 password hashing |
| Message Format | JSON payload |

## Running on Android (Termux)

cd ~/homelab/projects/encrypted-chat
pip install cryptography
python client.py -s <SERVER_IP> -p 5001 -u PhoneUser --password chat123

## Future Improvements

- RSA handshake for key exchange
- Chat groups
- Push notifications
- GUI interface
- n8n integration
- Certificate-based authentication

## Author

Robert Mircea
GitHub: felix-meow
LinkedIn: robert-mircea