#!/usr/bin/env python3
"""
Encrypted Chat - Server
Homelab Project

Multi-client chat server with end-to-end encryption and authentication.
"""

import socket
import threading
import json
import os
import time
from datetime import datetime
import sys
import argparse

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from utils import (
    encrypt_message, decrypt_message, generate_key, hash_password,
    load_public_key, rsa_encrypt, generate_session_key,
)


def recv_line(sock):
    """Read a single newline-terminated line from a socket.

    Returns (line_str, leftover_bytes) where leftover is any data received
    past the newline (belonging to the next message).
    """
    buf = b""
    while b"\n" not in buf:
        chunk = sock.recv(1024)
        if not chunk:
            break
        buf += chunk
    line, _, rest = buf.partition(b"\n")
    return line.decode(errors="ignore"), rest


class ChatServer:
    """Multi-client encrypted chat server with RSA key exchange and rooms."""

    def __init__(self, host='0.0.0.0', port=5000, password='chat123'):
        self.host = host
        self.port = port
        self.password = password
        self.clients = {}
        self.addresses = {}
        self.client_room = {}
        # room name -> shared Fernet session key (bytes), created on demand.
        self.room_keys = {}
        self.key = generate_key(password)
        self.running = True
        os.makedirs('logs', exist_ok=True)

    def get_room_key(self, room):
        """Return the shared session key for a room, creating it if needed."""
        if room not in self.room_keys:
            self.room_keys[room] = generate_session_key()
            print(f"[ROOM] Created session key for room '{room}'")
        return self.room_keys[room]

    def broadcast(self, message, sender_socket=None):
        """Send a message to clients in the sender's room, except the sender."""
        room = self.client_room.get(sender_socket)
        for client in list(self.clients):
            if client == sender_socket:
                continue
            # Only deliver within the same room.
            if room is not None and self.client_room.get(client) != room:
                continue
            try:
                client.send(message.encode())
            except Exception:
                self.remove_client(client)

    def remove_client(self, client_socket):
        """Remove a client and notify others."""
        if client_socket in self.clients:
            username = self.clients[client_socket]
            print(f"[{datetime.now().strftime('%H:%M:%S')}] {username} left the chat")

            payload = json.dumps({
                'type': 'system',
                'timestamp': datetime.now().strftime('%H:%M:%S'),
                'message': f"{username} left the chat"
            })
            self.broadcast(payload, client_socket)

            del self.clients[client_socket]
            if client_socket in self.addresses:
                del self.addresses[client_socket]
            if client_socket in self.client_room:
                del self.client_room[client_socket]
            client_socket.close()

    def handle_client(self, client_socket, address):
        """Handle a single client connection."""
        try:
            # Authentication
            data = client_socket.recv(1024).decode().strip()

            if '\n' in data:
                parts = data.split('\n')
                username = parts[0].strip()
                password = parts[1].strip() if len(parts) > 1 else ''
            else:
                username = data
                password = client_socket.recv(1024).decode().strip()

            print(f"[AUTH] Username: '{username}', Password: '{password}'")

            if hash_password(password) != hash_password(self.password):
                print(f"[AUTH] Failed for {username}")
                client_socket.send("AUTH_FAIL".encode())
                client_socket.close()
                return

            client_socket.send("AUTH_OK".encode())
            print(f"[AUTH] Success for {username}")

            # RSA key-exchange handshake: the client sends its room and RSA
            # public key; the server replies with the room's shared session
            # key, encrypted under that public key.
            handshake_line, pending = recv_line(client_socket)
            handshake = json.loads(handshake_line)
            room = handshake.get('room', 'general')
            client_pub = load_public_key(handshake['pubkey'])

            session_key = self.get_room_key(room)
            encrypted_key = rsa_encrypt(client_pub, session_key)
            client_socket.send((json.dumps({'session_key': encrypted_key}) + "\n").encode())
            print(f"[HANDSHAKE] {username} -> room '{room}', session key exchanged via RSA")

            self.clients[client_socket] = username
            self.addresses[client_socket] = address
            self.client_room[client_socket] = room

            print(f"[CONNECT] {username} from {address[0]}:{address[1]} in room '{room}'")

            welcome_payload = json.dumps({
                'type': 'system',
                'timestamp': datetime.now().strftime('%H:%M:%S'),
                'message': f"{username} joined the chat"
            })
            self.broadcast(welcome_payload, client_socket)

            # Message loop. Any bytes received past the handshake newline are
            # the first chat message and must be processed before recv().
            while self.running:
                try:
                    if pending:
                        message = pending.decode(errors="ignore")
                        pending = b""
                    else:
                        message = client_socket.recv(4096).decode()
                    if not message:
                        break

                    payload = json.dumps({
                        'type': 'chat',
                        'timestamp': datetime.now().strftime('%H:%M:%S'),
                        'username': username,
                        'message': message
                    })
                    self.broadcast(payload, client_socket)
                    print(f"[ENCRYPTED] from {username}")

                except Exception as e:
                    print(f"[ERROR] {e}")
                    break

        except Exception as e:
            print(f"[ERROR] Client {address}: {e}")
        finally:
            self.remove_client(client_socket)

    def start(self):
        """Start the chat server."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(10)

        print(f"""
========================================
  Encrypted Chat Server
========================================
  Host: {self.host}:{self.port}
  Password: {self.password}
  Clients: {len(self.clients)}
========================================
        """)
        print("[SERVER] Started. Waiting for connections...")
        print("[SERVER] Press Ctrl+C to stop\n")

        while self.running:
            try:
                client_socket, address = server.accept()
                print(f"[CONNECTION] from {address[0]}:{address[1]}")
                thread = threading.Thread(target=self.handle_client, args=(client_socket, address))
                thread.daemon = True
                thread.start()
            except KeyboardInterrupt:
                print("\n[SERVER] Stopping...")
                self.running = False
                break
            except Exception as e:
                print(f"[ERROR] {e}")

        server.close()
        print("[SERVER] Stopped.")


def main():
    parser = argparse.ArgumentParser(description="Encrypted Chat Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("-p", "--port", type=int, default=5001, help="Port to listen on")
    parser.add_argument("--password", default="chat123", help="Server password")

    args = parser.parse_args()

    server = ChatServer(args.host, args.port, args.password)
    server.start()


if __name__ == "__main__":
    main()