# Encrypted Chat

End-to-end encrypted chat system with authentication, multi-client support, and cross-platform compatibility.

## Trust model (read first)

The message key is derived **on each client** from a shared secret (passphrase +
salt) via PBKDF2 and is **never sent over the wire**. The server authenticates
clients and relays **ciphertext only** — it never derives, receives, or holds
the message key, so a compromised/malicious server operator sees sealed Fernet
tokens, nothing else. This is the property that makes it genuinely end-to-end.

Two independent secrets, do not confuse them:

- `--password` — **auth** password. Proves you may connect. The server knows it.
  Not used for message encryption.
- `--secret` + `--salt` — **encryption** material. Agreed out-of-band / in person
  between the two peers. Never sent to the server. The `salt` is used as an
  intentional shared *pepper*, not a public salt. The client refuses to start on
  the demo defaults.

**Honest limitations:** no forward secrecy / post-compromise recovery (if the
shared secret leaks, all messages under it are exposed — a symmetric ratchet
would fix this); the server still sees metadata (who/when/which room); there is
no TLS on the socket, so the auth password travels in cleartext — put this
behind a tunnel for real use.

## Purpose

This tool is part of my cybersecurity homelab portfolio. It demonstrates:

- End-to-end encryption (AES-128 via Fernet), key never leaves the client
- Key derivation (PBKDF2-HMAC-SHA256)
- Client-server (dumb-relay) architecture
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

Both peers use the same --secret and --salt (agreed in person), each their own username:

python3 client.py -s 127.0.0.1 -p 5001 -u Alice \
    --password chat123 --secret 'our-shared-passphrase' --salt 'pick-a-pepper'

### Options

Server:
  --host         Host to bind to (default: 0.0.0.0)
  -p, --port     Port to listen on (default: 5001)
  --password     AUTH password (server access only; default: chat123)

Client:
  -s, --server   Server IP address (default: 127.0.0.1)
  -p, --port     Server port (default: 5001)
  -u, --username Your username
  -r, --room     Chat room to join (default: general)
  --password     AUTH password (server access only; default: chat123)
  --secret       ENCRYPTION passphrase, shared out-of-band. Never sent.
  --salt         Shared secret salt/pepper, agreed in person. Never sent.
  --i-understand-demo-defaults   Allow insecure demo secret/salt (local testing only)

### Key derivation & rooms

There is **no key exchange with the server**. Each client derives the Fernet key
locally from `--secret` + `--salt` (PBKDF2). Two peers who set the same secret
and salt derive the same key and can read each other; the server cannot, because
it never receives either value. Rooms (`-r/--room`) only scope who the relay
forwards a message to — they are not a security boundary by themselves (anyone
with the shared secret can read; use a distinct secret per conversation).

### Client Commands

| Command | Description |
|---------|-------------|
| /quit | Exit the chat |
| /help | Show available commands |
| /clear | Clear the screen |

## Example Session

Server (relay — only ever sees ciphertext):
[CONNECT] Alice from 127.0.0.1:55256 in room 'general'
[RELAY] ciphertext from Alice (120 bytes)

Client Alice:
[CONNECT] 127.0.0.1:5001 as Alice
[READY] room 'general' | E2EE key derived locally (server never sees it)

[21:00:20] Bob: Salut Alice!

## Security

| Feature | Implementation |
|---------|----------------|
| Encryption | AES-128-CBC + HMAC-SHA256 (Fernet) |
| Key Derivation | PBKDF2-HMAC-SHA256 (200k iterations), key stays on client |
| Server role | Dumb relay — never holds the message key |
| Authentication | SHA256 of a separate auth password |
| Message Format | JSON payload carrying an opaque Fernet token |

## Running on Android (Termux)

cd ~/homelab/projects/standalone/encrypted-chat
pip install cryptography
python client.py -s <SERVER_IP> -p 5001 -u PhoneUser \
    --password chat123 --secret 'our-shared-passphrase' --salt 'pick-a-pepper'

## Future Improvements

- Symmetric ratchet for forward secrecy / post-compromise security
- TLS (or run over an SSH/WireGuard tunnel) to protect the auth password + metadata
- Authenticated per-pair key agreement (X25519 + verified fingerprints) instead of a shared passphrase
- Push notifications, GUI, n8n integration

