#!/usr/bin/env python3
"""
Encrypted Chat - Server (dumb relay)
Homelab Project

The server authenticates clients and relays ciphertext within rooms. It does
NOT derive, hold, or ever see the message-encryption key: that lives only on
the clients (see utils.py). A compromised/malicious server operator sees only
sealed Fernet tokens -> true end-to-end encryption.

What the server legitimately knows (metadata, be aware of it):
  * which usernames/IPs connect, when, and which room they join.
Hiding that requires an onion/mix transport and is out of scope for this PoC.
"""

import socket
import threading
import json
import os
import sys
import argparse
from datetime import datetime

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from utils import hash_password


def recv_line(sock):
    """Read one newline-terminated line. Returns (line_str, leftover_bytes)."""
    buf = b""
    while b"\n" not in buf:
        chunk = sock.recv(1024)
        if not chunk:
            break
        buf += chunk
    line, _, rest = buf.partition(b"\n")
    return line.decode(errors="ignore"), rest


class ChatServer:
    """Multi-client relay with password auth and rooms. Holds no crypto keys."""

    def __init__(self, host='0.0.0.0', port=5001, password='chat123'):
        self.host = host
        self.port = port
        self.password = password
        self.clients = {}        # socket -> username
        self.addresses = {}      # socket -> (ip, port)
        self.client_room = {}    # socket -> room
        self.lock = threading.Lock()  # guards the three dicts across client threads
        self.running = True

    def broadcast(self, message, sender_socket=None, room=None):
        """Send to clients in the sender's room (or `room`), except the sender."""
        with self.lock:
            if room is None:
                room = self.client_room.get(sender_socket)
            targets = [c for c in self.clients
                       if c != sender_socket and (room is None or self.client_room.get(c) == room)]
        for client in targets:
            try:
                client.send(message.encode())
            except Exception:
                self.remove_client(client)

    def remove_client(self, client_socket):
        """Remove a client and notify its room. Safe when two threads race to remove
        the same client (e.g. a failed broadcast and the client's own handler)."""
        with self.lock:
            username = self.clients.pop(client_socket, None)
            room = self.client_room.pop(client_socket, None)
            self.addresses.pop(client_socket, None)
        if username is None:
            return  # already removed by another thread
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {username} left the chat")
        payload = json.dumps({
            'type': 'system',
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'message': f"{username} left the chat",
        })
        self.broadcast(payload, client_socket, room=room)
        try:
            client_socket.close()
        except OSError:
            pass

    def handle_client(self, client_socket, address):
        """Authenticate, register the room, then relay ciphertext."""
        try:
            # --- Authentication (auth password only; NOT the message secret) ---
            data = client_socket.recv(1024).decode().strip()
            if '\n' in data:
                parts = data.split('\n')
                username = parts[0].strip()
                password = parts[1].strip() if len(parts) > 1 else ''
            else:
                username = data
                password = client_socket.recv(1024).decode().strip()

            if hash_password(password) != hash_password(self.password):
                print(f"[AUTH] Failed for {username!r}")
                client_socket.send("AUTH_FAIL".encode())
                client_socket.close()
                return

            client_socket.send("AUTH_OK".encode())

            # --- Room handshake: client announces its room. No key exchange: the
            #     server never participates in message-key setup. Bytes received
            #     past the handshake newline are the first chat frame. ---
            handshake_line, pending = recv_line(client_socket)
            handshake = json.loads(handshake_line)
            room = handshake.get('room', 'general')

            with self.lock:
                self.clients[client_socket] = username
                self.addresses[client_socket] = address
                self.client_room[client_socket] = room
            print(f"[CONNECT] {username} from {address[0]}:{address[1]} in room '{room}'")

            self.broadcast(json.dumps({
                'type': 'system',
                'timestamp': datetime.now().strftime('%H:%M:%S'),
                'message': f"{username} joined the chat",
            }), client_socket)

            # --- Relay loop: forward the opaque ciphertext, never decrypt it. ---
            while self.running:
                try:
                    if pending:
                        message = pending.decode(errors="ignore")
                        pending = b""
                    else:
                        message = client_socket.recv(4096).decode()
                    if not message:
                        break

                    self.broadcast(json.dumps({
                        'type': 'chat',
                        'timestamp': datetime.now().strftime('%H:%M:%S'),
                        'username': username,
                        'message': message,   # opaque Fernet token; server can't read it
                    }), client_socket)
                    print(f"[RELAY] ciphertext from {username} ({len(message)} bytes)")
                except Exception as e:
                    print(f"[ERROR] {e}")
                    break

        except Exception as e:
            print(f"[ERROR] Client {address}: {e}")
        finally:
            self.remove_client(client_socket)

    def start(self):
        if self.password == 'chat123':
            print("[WARN] Using the default auth password 'chat123'. "
                  "Set --password for anything real.")
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(10)
        print(f"""
========================================
  Encrypted Chat Relay (sees ciphertext only)
========================================
  Host: {self.host}:{self.port}
========================================
[SERVER] Started. Ctrl+C to stop.
""")
        while self.running:
            try:
                client_socket, address = server.accept()
                print(f"[CONNECTION] from {address[0]}:{address[1]}")
                t = threading.Thread(target=self.handle_client, args=(client_socket, address))
                t.daemon = True
                t.start()
            except KeyboardInterrupt:
                print("\n[SERVER] Stopping...")
                self.running = False
                break
            except Exception as e:
                print(f"[ERROR] {e}")
        server.close()
        print("[SERVER] Stopped.")


def main():
    parser = argparse.ArgumentParser(description="Encrypted Chat Relay")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("-p", "--port", type=int, default=5001, help="Port to listen on")
    parser.add_argument("--password", default="chat123",
                        help="AUTH password (server access only; not the message secret)")
    args = parser.parse_args()
    ChatServer(args.host, args.port, args.password).start()


if __name__ == "__main__":
    main()
