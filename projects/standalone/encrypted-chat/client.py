#!/usr/bin/env python3
"""
Encrypted Chat - Client (end-to-end encryption)
Homelab Project

The client derives the message key locally from a shared secret and only ever
sends ciphertext. Two independent secrets:

  --password   AUTH password: proves to the relay you may connect. The server
               knows it. It is NOT used for message encryption.
  --secret     ENCRYPTION passphrase: used with --salt to derive the Fernet key
               via PBKDF2. NEVER sent over the wire; the server never learns it.
               Both peers must set the same --secret and --salt (agreed
               out-of-band / in person).

As long as --secret and --salt stay off the demo defaults and off the server
operator, the operator sees only sealed tokens.
"""

import socket
import threading
import sys
import os
import json
import argparse
from datetime import datetime

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from utils import encrypt_message, decrypt_message, generate_key, DEFAULT_SALT

DEMO_SECRET = 'change-me'


class ChatClient:
    """E2EE chat client. Derives its key locally; server never sees it."""

    def __init__(self, host, port, auth_password, secret, salt, username, room):
        self.host = host
        self.port = port
        self.auth_password = auth_password
        self.username = username
        self.room = room
        self.socket = None
        # Message key: derived here, from the shared secret. Never transmitted.
        self.key = generate_key(secret, salt)
        self.running = True
        self.authenticated = False

    def receive_messages(self):
        """Receive frames from the relay and decrypt the ciphertext locally."""
        while self.running:
            try:
                data = self.socket.recv(4096).decode()
                if not data:
                    break
                try:
                    obj = json.loads(data)
                    if obj.get('type') == 'system':
                        print(f"\n{obj['message']}")
                    else:
                        decrypted = decrypt_message(obj['message'], self.key)
                        print(f"\n[{obj['timestamp']}] {obj['username']}: {decrypted}")
                except json.JSONDecodeError:
                    print(f"\n{data}")
                except Exception as e:
                    # Wrong secret/salt, or tampered token -> Fernet raises here.
                    print(f"\n[DECRYPT FAILED: {e}]")
                print(f"[{datetime.now().strftime('%H:%M:%S')}] You: ", end='', flush=True)
            except Exception as e:
                print(f"\n[ERROR] Reception: {e}")
                break
        print("\n[DISCONNECTED] Connection lost.")

    def send_messages(self):
        """Encrypt locally, then send only ciphertext."""
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
                    self.socket.send(encrypt_message(msg, self.key).encode())
            except Exception as e:
                print(f"[ERROR] Transmission: {e}")
                break

    def connect(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.socket.connect((self.host, self.port))
            print(f"[CONNECT] {self.host}:{self.port} as {self.username}")

            # Auth (auth password only).
            self.socket.send(f"{self.username}\n{self.auth_password}".encode())
            response = self.socket.recv(1024).decode()
            if "AUTH_OK" not in response:
                print("[AUTH] Authentication failed!")
                return
            self.authenticated = True

            # Announce room. No key exchange with the server.
            self.socket.send((json.dumps({'room': self.room}) + "\n").encode())
            print(f"[READY] room '{self.room}' | E2EE key derived locally "
                  f"(server never sees it)")

            threading.Thread(target=self.receive_messages, daemon=True).start()
            self.send_messages()
        except ConnectionRefusedError:
            print(f"[ERROR] Connection refused at {self.host}:{self.port}")
        except Exception as e:
            print(f"[ERROR] {e}")
        finally:
            if self.socket:
                self.socket.close()


def main():
    parser = argparse.ArgumentParser(description="Encrypted Chat Client (E2EE)")
    parser.add_argument("-s", "--server", default="127.0.0.1", help="Server IP")
    parser.add_argument("-p", "--port", type=int, default=5001, help="Server port")
    parser.add_argument("--password", default="chat123",
                        help="AUTH password (server access; not the message secret)")
    parser.add_argument("--secret", default=DEMO_SECRET,
                        help="ENCRYPTION passphrase, shared out-of-band. Never sent.")
    parser.add_argument("--salt", default=None,
                        help="Shared secret salt/pepper, agreed in person. Never sent.")
    parser.add_argument("-u", "--username", default="User", help="Your username")
    parser.add_argument("-r", "--room", default="general", help="Room to join")
    parser.add_argument("--i-understand-demo-defaults", action="store_true",
                        help="Allow running with the insecure demo secret/salt (testing only).")
    args = parser.parse_args()

    salt = args.salt.encode() if args.salt else None

    # Refuse to run with public demo defaults for the message secret/salt.
    using_default_secret = (args.secret == DEMO_SECRET)
    using_default_salt = (salt is None or salt == DEFAULT_SALT)
    if (using_default_secret or using_default_salt) and not args.i_understand_demo_defaults:
        problems = []
        if using_default_secret:
            problems.append("--secret is the demo default")
        if using_default_salt:
            problems.append("--salt is unset/default (a public, well-known value)")
        print("[REFUSED] " + "; ".join(problems) + ".")
        print("          Set a unique --secret and --salt (agreed out-of-band with your peer),")
        print("          or pass --i-understand-demo-defaults for local testing only.")
        sys.exit(1)

    ChatClient(args.server, args.port, args.password, args.secret, salt,
               args.username, args.room).connect()


if __name__ == "__main__":
    main()
