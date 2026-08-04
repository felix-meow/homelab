#!/usr/bin/env python3
"""
Encrypted Chat - Client
Homelab Project

Client for the encrypted chat system with end-to-end encryption.
"""

import socket
import threading
import sys
import os
import json
import argparse
from datetime import datetime

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from utils import encrypt_message, decrypt_message, generate_key


class ChatClient:
    """Encrypted chat client."""

    def __init__(self, host='127.0.0.1', port=5000, password='chat123', username='User'):
        self.host = host
        self.port = port
        self.password = password
        self.username = username
        self.socket = None
        self.key = generate_key(password)
        self.running = True
        self.authenticated = False

    def receive_messages(self):
        """Receive and decrypt messages from the server."""
        while self.running:
            try:
                data = self.socket.recv(4096).decode()
                if not data:
                    break

                try:
                    data_obj = json.loads(data)

                    if data_obj.get('type') == 'system':
                        print(f"\n{data_obj['message']}")
                    else:
                        decrypted = decrypt_message(data_obj['message'], self.key)
                        print(f"\n[{data_obj['timestamp']}] {data_obj['username']}: {decrypted}")

                except json.JSONDecodeError:
                    print(f"\n{data}")
                except Exception as e:
                    print(f"\n{data} [DECRYPT FAILED: {e}]")

                print(f"[{datetime.now().strftime('%H:%M:%S')}] You: ", end='', flush=True)

            except Exception as e:
                print(f"\n[ERROR] Reception: {e}")
                break

        print("\n[DISCONNECTED] Connection lost.")

    def send_messages(self):
        """Encrypt and send messages to the server."""
        while self.running and self.authenticated:
            try:
                msg = input()

                if msg.lower() == '/quit':
                    self.running = False
                    break
                elif msg.lower() == '/help':
                    print("Commands: /quit, /help, /clear")
                    continue
                elif msg.lower() == '/clear':
                    os.system('clear' if os.name == 'posix' else 'cls')
                    continue
                elif msg:
                    encrypted = encrypt_message(msg, self.key)
                    self.socket.send(encrypted.encode())

            except Exception as e:
                print(f"[ERROR] Transmission: {e}")
                break

    def connect(self):
        """Connect to the server and authenticate."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            self.socket.connect((self.host, self.port))
            print(f"[CONNECT] Connected to {self.host}:{self.port}")
            print(f"[AUTH] Authenticating as {self.username}...")

            credentials = f"{self.username}\n{self.password}"
            self.socket.send(credentials.encode())

            response = self.socket.recv(1024).decode()
            print(f"[AUTH] Server response: {response}")

            if "AUTH_OK" in response:
                self.authenticated = True
                print("[AUTH] Successfully authenticated!")

                print(f"""
========================================
  Encrypted Chat Client
========================================
  Server: {self.host}:{self.port}
  User: {self.username}
========================================
                """)

                threading.Thread(target=self.receive_messages, daemon=True).start()
                self.send_messages()
            else:
                print("[AUTH] Authentication failed!")

        except ConnectionRefusedError:
            print(f"[ERROR] Connection refused! Server not running at {self.host}:{self.port}")
        except Exception as e:
            print(f"[ERROR] Connection error: {e}")
        finally:
            if self.socket:
                self.socket.close()


def main():
    parser = argparse.ArgumentParser(description="Encrypted Chat Client")
    parser.add_argument("-s", "--server", default="127.0.0.1", help="Server IP address")
    parser.add_argument("-p", "--port", type=int, default=5001, help="Server port")
    parser.add_argument("--password", default="chat123", help="Server password")
    parser.add_argument("-u", "--username", default="User", help="Your username")

    args = parser.parse_args()

    client = ChatClient(args.server, args.port, args.password, args.username)
    client.connect()


if __name__ == "__main__":
    main()