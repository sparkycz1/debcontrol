"""Encryption for sensitive data stored in the database (SSH passwords, private keys).

We use Fernet (AES-128-CBC + HMAC, authenticated encryption) from the
`cryptography` package. The key is NEVER stored in the DB or the repo —
only in `ENCRYPTION_KEY` in the environment. This application doesn't have
user authentication yet, but secrets belonging to *managed* machines
(their passwords/keys) are encrypted at rest from the very first commit.

Note: this is NOT a substitute for authenticating/authorizing users of this
app — that's a later phase. It only protects data at rest in Postgres.
"""

from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import get_settings


class DecryptionError(Exception):
    """Decryption failed — corrupted/tampered data, or the wrong key."""


def _fernet() -> Fernet:
    key = get_settings().encryption_key.get_secret_value()
    return Fernet(key.encode("utf-8"))


def encrypt_secret(plaintext: str) -> bytes:
    """Encrypt a sensitive string (password, private key) for storage in the DB."""
    return _fernet().encrypt(plaintext.encode("utf-8"))


def decrypt_secret(ciphertext: bytes) -> str:
    """Decrypt a value stored via `encrypt_secret`."""
    try:
        return _fernet().decrypt(ciphertext).decode("utf-8")
    except InvalidToken as exc:
        raise DecryptionError("Failed to decrypt the stored secret.") from exc
