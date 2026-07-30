"""
===============================================================================
File: password.py

Project:
SentinelDNS

Purpose:
Centralized password hashing and verification utilities.

Responsibilities:
- Hash passwords securely.
- Verify password hashes.
- Abstract the underlying hashing implementation.

Security Notes:
- Uses Argon2id via pwdlib.
- Never stores plaintext passwords.
- No custom cryptographic implementation.

===============================================================================
"""

from __future__ import annotations

from pwdlib import PasswordHash

# Single shared password hasher instance.
_password_hasher = PasswordHash.recommended()


def hash_password(password: str) -> str:
    """
    Hash a plaintext password using Argon2id.

    Args:
        password: Plaintext password.

    Returns:
        Secure password hash.
    """
    return _password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """
    Verify a plaintext password against its stored hash.

    Args:
        password: Plaintext password.
        password_hash: Stored Argon2id password hash.

    Returns:
        True if the password is valid, otherwise False.
    """
    return _password_hasher.verify(password, password_hash)