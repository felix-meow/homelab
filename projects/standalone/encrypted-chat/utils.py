#!/usr/bin/env python3
"""
Encrypted Chat - Utils
Homelab Project

Cryptographic utilities for key derivation, encryption, decryption, and
password hashing.

Trust model (read this before touching the crypto):
  * The message-encryption key is derived HERE, on each client, from a shared
    secret (passphrase + salt). It is NEVER sent over the wire and the server
    never receives the passphrase or the salt. The server is a dumb relay that
    only ever sees ciphertext -> true end-to-end encryption against the server
    operator.
  * `salt` is used as an intentional, out-of-band shared "pepper": the two
    humans agree on it in person (convention) and pass it via --salt. It is
    secret material, NOT a public per-user salt. That is a deliberate design
    choice for this PoC, not an oversight. Because it is secret and
    pair-unique, it adds entropy to the derived key. Leaving it at the default
    is the only real risk -> the client refuses to start on the default
    (see client.py).

Known limitations (honest, not E2EE-breaking):
  * Fernet = AES-128-CBC + HMAC-SHA256. No per-message forward secrecy and no
    post-compromise recovery: if the shared secret leaks, every message under
    it is exposed. A symmetric ratchet (future work) would fix this.
"""

import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Demo default. Treated as "unset": the client refuses to run on it so a real
# deployment cannot accidentally ship with a public, well-known salt/pepper.
DEFAULT_SALT = b'salt_1234567890'


def generate_key(passphrase: str, salt: bytes = None) -> bytes:
    """
    Derive a Fernet key from a shared passphrase using PBKDF2-HMAC-SHA256.

    Args:
        passphrase: The shared encryption secret (never transmitted).
        salt: Shared secret pepper agreed out-of-band. Defaults to DEFAULT_SALT
              (demo only; callers should reject the default in production).

    Returns:
        A URL-safe base64-encoded 32-byte key suitable for Fernet.
    """
    if salt is None:
        salt = DEFAULT_SALT

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000,
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))


def encrypt_message(message: str, key: bytes) -> str:
    """Encrypt a message using Fernet (AES-128-CBC + HMAC)."""
    return Fernet(key).encrypt(message.encode()).decode()


def decrypt_message(encrypted_message: str, key: bytes) -> str:
    """Decrypt a Fernet token. Raises on tampering/wrong key (authenticated)."""
    return Fernet(key).decrypt(encrypted_message.encode()).decode()


def hash_password(password: str) -> str:
    """Hash the *auth* password (server access control, not message crypto)."""
    return hashlib.sha256(password.encode()).hexdigest()
