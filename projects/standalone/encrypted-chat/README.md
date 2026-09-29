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
  -r, --room     Chat room to join (default: general)
  --password     Server password (default: chat123)

### Key exchange & rooms

After authentication the client generates an RSA-2048 key pair and sends its
public key to the server. The server holds one shared AES (Fernet) session key
per room and returns it encrypted with the client's public key (RSA-OAEP). All
members of a room therefore share the same session key, so messages are
broadcast only within a room and stay encrypted end to end. Clients in
different rooms hold different keys and cannot read each other's traffic.

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

cd ~/homelab/projects/standalone/encrypted-chat
pip install cryptography
python client.py -s <SERVER_IP> -p 5001 -u PhoneUser --password chat123

## Implemented

- RSA handshake for session-key exchange (RSA-2048 / OAEP)
- Chat groups (per-room shared session key, `-r/--room`)

## Future Improvements

- Push notifications
- GUI interface
- n8n integration
- Certificate-based authentication

