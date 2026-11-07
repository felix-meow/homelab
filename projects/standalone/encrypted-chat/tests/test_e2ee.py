"""End-to-end encryption tests for the encrypted chat.

They check the trust model the README claims:
  * the message key is derived on the client and never sent over the wire;
  * the relay holds no key and only ever forwards ciphertext;
  * a peer with the same secret + salt can read a message, anyone else cannot.
Everything runs on 127.0.0.1 with ephemeral ports.
"""

import builtins
import json
import os
import socket
import sys
import threading
import time

import pytest
from cryptography.fernet import InvalidToken

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import client as chat_client  # noqa: E402
import server as chat_server  # noqa: E402
import utils  # noqa: E402

SECRET = "correct horse battery staple"
SALT = b"pepper-agreed-in-person"
AUTH = "auth-only-password"
PLAINTEXT = "meet at the usual place at 21:00"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_until(cond, timeout=5.0):
    deadline = time.time() + timeout
    while not cond():
        if time.time() > deadline:
            raise AssertionError("condition not met in time")
        time.sleep(0.02)


@pytest.fixture
def relay():
    port = free_port()
    srv = chat_server.ChatServer("127.0.0.1", port, AUTH)
    threading.Thread(target=srv.start, daemon=True).start()
    return srv, port


def connect_peer(port, name, room="r1"):
    deadline = time.time() + 5
    while True:
        try:
            sock = socket.create_connection(("127.0.0.1", port), timeout=5)
            break
        except OSError:
            if time.time() > deadline:
                raise
            time.sleep(0.05)
    sock.sendall(f"{name}\n{AUTH}".encode())
    assert sock.recv(1024) == b"AUTH_OK"
    sock.sendall((json.dumps({"room": room}) + "\n").encode())
    return sock


def read_chat_message(sock, timeout=5.0):
    """Return the first 'chat' frame the relay delivers (frames are bare JSON objects)."""
    sock.settimeout(timeout)
    buf, decoder = "", json.JSONDecoder()
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            raise AssertionError("relay closed the connection")
        buf += chunk.decode()
        while buf.strip():
            buf = buf.lstrip()
            try:
                obj, end = decoder.raw_decode(buf)
            except json.JSONDecodeError:
                break  # incomplete frame: read more
            buf = buf[end:]
            if obj.get("type") == "chat":
                return obj


def test_relay_forwards_only_ciphertext(relay, capsys):
    srv, port = relay
    alice, bob = connect_peer(port, "alice"), connect_peer(port, "bob")
    wait_until(lambda: len(srv.clients) == 2)

    key = utils.generate_key(SECRET, SALT)
    token = utils.encrypt_message(PLAINTEXT, key)
    alice.sendall(token.encode())
    frame = read_chat_message(bob)

    assert frame["message"] == token  # forwarded opaque and unchanged
    assert PLAINTEXT not in json.dumps(frame)
    assert utils.decrypt_message(frame["message"], key) == PLAINTEXT  # the peer can read it
    logged = capsys.readouterr().out
    assert PLAINTEXT not in logged and AUTH not in logged  # nothing sensitive in relay logs
    alice.close()
    bob.close()


def test_messages_stay_in_their_room(relay):
    srv, port = relay
    a1, a2 = connect_peer(port, "a1", "room-a"), connect_peer(port, "a2", "room-a")
    b1 = connect_peer(port, "b1", "room-b")
    wait_until(lambda: len(srv.clients) == 3)

    a1.sendall(b"gAAAAA-opaque-token-for-room-a")
    assert read_chat_message(a2)["message"] == "gAAAAA-opaque-token-for-room-a"
    with pytest.raises(TimeoutError):
        read_chat_message(b1, timeout=0.5)
    for s in (a1, a2, b1):
        s.close()


def test_simultaneous_disconnects_do_not_crash_relay(relay, monkeypatch):
    # Regression: a failed broadcast and the client's own handler used to race to
    # remove the same client, raising KeyError in a relay thread.
    srv, port = relay
    errors = []
    monkeypatch.setattr(threading, "excepthook", lambda args: errors.append(args.exc_value))
    peers = [connect_peer(port, f"p{i}") for i in range(4)]
    wait_until(lambda: len(srv.clients) == 4)
    for p in peers:
        p.close()
    wait_until(lambda: len(srv.clients) == 0)
    time.sleep(0.3)  # let the handler threads finish
    assert errors == []


def test_relay_holds_no_key_material(relay):
    srv, _ = relay
    # Regression guard: an earlier version generated the session key on the server.
    assert not hasattr(srv, "key")
    for name in ("generate_key", "decrypt_message", "encrypt_message", "Fernet"):
        assert not hasattr(chat_server, name), f"server must not use {name}"


def test_client_never_sends_secret_or_salt(monkeypatch):
    port = free_port()
    wire = bytearray()
    listener = socket.socket()
    listener.bind(("127.0.0.1", port))
    listener.listen(1)

    def recording_relay():
        conn, _ = listener.accept()
        with conn:
            wire.extend(conn.recv(1024))  # auth
            conn.sendall(b"AUTH_OK")
            conn.settimeout(2)
            try:
                while chunk := conn.recv(4096):
                    wire.extend(chunk)
            except socket.timeout:
                pass

    t = threading.Thread(target=recording_relay, daemon=True)
    t.start()
    typed = iter([PLAINTEXT, "/quit"])
    monkeypatch.setattr(builtins, "input", lambda *args: next(typed))

    chat_client.ChatClient("127.0.0.1", port, AUTH, SECRET, SALT, "alice", "r1").connect()
    t.join(5)
    listener.close()

    sent = bytes(wire)
    assert SECRET.encode() not in sent
    assert SALT not in sent
    assert PLAINTEXT.encode() not in sent
    assert b"gAAAAA" in sent  # but a Fernet token did go out


@pytest.mark.parametrize("secret, salt", [("wrong secret", SALT), (SECRET, b"other-pepper")])
def test_outsider_without_secret_and_salt_cannot_read(secret, salt):
    token = utils.encrypt_message(PLAINTEXT, utils.generate_key(SECRET, SALT))
    with pytest.raises(InvalidToken):
        utils.decrypt_message(token, utils.generate_key(secret, salt))


def test_tampered_ciphertext_is_rejected():
    key = utils.generate_key(SECRET, SALT)
    token = utils.encrypt_message(PLAINTEXT, key)
    i = len(token) // 2
    tampered = token[:i] + ("A" if token[i] != "A" else "B") + token[i + 1:]
    with pytest.raises(InvalidToken):
        utils.decrypt_message(tampered, key)


def test_client_refuses_demo_secret_and_salt(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["client.py"])
    with pytest.raises(SystemExit) as exc:
        chat_client.main()
    assert exc.value.code == 1
