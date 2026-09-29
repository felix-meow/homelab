#!/usr/bin/env python3
"""
Encrypted Chat - Utils
Homelab Project

Cryptographic utilities for key generation, encryption, decryption, and password hashing.
"""

import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
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


# --- RSA key-exchange helpers -------------------------------------------------

def generate_rsa_keypair():
    """Generate a 2048-bit RSA private/public key pair."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


def serialize_public_key(public_key) -> str:
    """Serialize an RSA public key to a base64 string (PEM under the hood)."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(pem).decode()


def load_public_key(data: str):
    """Load an RSA public key from a base64-encoded PEM string."""
    pem = base64.b64decode(data.encode())
    return serialization.load_pem_public_key(pem)


def rsa_encrypt(public_key, data: bytes) -> str:
    """Encrypt bytes with an RSA public key (OAEP). Returns base64 string."""
    ciphertext = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return base64.b64encode(ciphertext).decode()


def rsa_decrypt(private_key, data: str) -> bytes:
    """Decrypt a base64 RSA-OAEP ciphertext with the private key."""
    ciphertext = base64.b64decode(data.encode())
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def generate_session_key() -> bytes:
    """Generate a fresh random Fernet (AES-128) session key."""
    return Fernet.generate_key()