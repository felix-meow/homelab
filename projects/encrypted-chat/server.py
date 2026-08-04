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
from utils import encrypt_message, decrypt_message, generate_key, hash_password


class ChatServer:
    """Multi-client encrypted chat server."""

    def __init__(self, host='0.0.0.0', port=5000, password='chat123'):
        self.host = host
        self.port = port
        self.password = password
        self.clients = {}
        self.addresses = {}
        self.key = generate_key(password)
        self.running = True
        os.makedirs('logs', exist_ok=True)

    def broadcast(self, message, sender_socket=None):
        """Send a message to all connected clients except the sender."""
        for client in self.clients:
            if client != sender_socket:
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

            self.clients[client_socket] = username
            self.addresses[client_socket] = address

            print(f"[CONNECT] {username} from {address[0]}:{address[1]}")

            welcome_payload = json.dumps({
                'type': 'system',
                'timestamp': datetime.now().strftime('%H:%M:%S'),
                'message': f"{username} joined the chat"
            })
            self.broadcast(welcome_payload, client_socket)

            # Message loop
            while self.running:
                try:
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