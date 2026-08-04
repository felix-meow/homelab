#!/usr/bin/env python3
"""
Encrypted Chat - Utils
Homelab Project

Cryptographic utilities for key generation, encryption, decryption, and password hashing.
"""

import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def generate_key(password: str, salt: bytes = None) -> bytes:
    """
    Generate a cryptographic key from a password using PBKDF2.

    Args:
        password: The password string.
        salt: Optional salt (defaults to a fixed salt).

    Returns:
        A URL-safe base64-encoded key.
    """
    if salt is None:
        salt = b'salt_1234567890'

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key


def encrypt_message(message: str, key: bytes) -> str:
    """Encrypt a message using Fernet (AES-128)."""
    f = Fernet(key)
    encrypted = f.encrypt(message.encode())
    return encrypted.decode()


def decrypt_message(encrypted_message: str, key: bytes) -> str:
    """Decrypt a message using Fernet (AES-128)."""
    f = Fernet(key)
    decrypted = f.decrypt(encrypted_message.encode())
    return decrypted.decode()


def hash_password(password: str) -> str:
    """Hash a password using SHA256."""
    return hashlib.sha256(password.encode()).hexdigest()