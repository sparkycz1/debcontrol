"""Encryption for sensitive data stored in the database (SSH passwords,
private keys, TOTP secrets, third-party API keys — every `LargeBinary`
`*_encrypted` column across `app/db/models/`).

New values are encrypted with **AES-256-GCM** (`cryptography`'s
`AESGCM`) — a random 12-byte nonce per value, keyed with the full 32 raw
bytes behind `ENCRYPTION_KEY`. `decrypt_secret` also still reads the
**Fernet** (AES-128-CBC + HMAC-SHA256) format every value here was
encrypted with before this change, so nothing already in the database
needs an immediate migration — `scripts/reencrypt_secrets.py` proactively
upgrades every remaining legacy value in one pass for a deployment that
wants none left, but running it is optional, not required, and nothing
here ever silently re-encrypts a value just because it was read.

Why AES-256, not just keep Fernet: Fernet's own construction always
splits its 32-byte key into two 16-byte halves and only ever encrypts
with the AES-**128** half — the other half only ever signs. AES-256-GCM
uses the full 32 bytes as a single AES-256 key, and (being AEAD) needs no
separate MAC step. See wiki/Architecture's "FIPS alignment" section for
the full reasoning — both AES-128 and AES-256 are themselves FIPS-approved
ciphers; this is a "prefer the modern default", not a "fixing something
broken", change.

`ENCRYPTION_KEY` itself is unchanged — still whatever
`scripts/generate_secrets.py` has always produced
(`Fernet.generate_key()`, a url-safe-base64-encoded 32 random bytes), just
now also decoded straight to those 32 raw bytes for AES-256-GCM rather
than handed to `Fernet()` as-is. No new environment variable, no key
rotation needed to pick this up.

The key is NEVER stored in the DB or the repo — only in `ENCRYPTION_KEY`
in the environment.

Note: this is NOT a substitute for authenticating/authorizing users of this
app — that's a separate concern. It only protects data at rest in Postgres.
"""

from __future__ import annotations

import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import get_settings

# The one-byte marker every value `encrypt_secret` produces is prefixed
# with, distinguishing it from a legacy Fernet token. Never ambiguous: a
# real Fernet token's first byte is always 0x80 (Fernet's own fixed format
# version byte — see `cryptography.fernet.Fernet._get_unverified_token_data`),
# so no value this module has ever produced, old or new, can collide with it.
_AESGCM_VERSION = b"\x02"
_NONCE_LENGTH = 12


class DecryptionError(Exception):
    """Decryption failed — corrupted/tampered data, or the wrong key."""


def current_encryption_key() -> str:
    """This instance's `ENCRYPTION_KEY` — a full backup carries it so a
    restore elsewhere can re-encrypt every secret under its own key
    (`app.services.full_backup`)."""
    return get_settings().encryption_key.get_secret_value()


def encrypt_secret(plaintext: str) -> bytes:
    """Encrypt a sensitive string (password, private key, ...) for storage
    in the DB. Always writes the current AES-256-GCM format — see the
    module docstring."""
    return encrypt_secret_with_key(plaintext, current_encryption_key())


def decrypt_secret(ciphertext: bytes) -> str:
    """Decrypt a value stored via `encrypt_secret` — transparently reads
    both the current AES-256-GCM format and a value still stored in the
    legacy Fernet format, without ever rewriting it. See the module
    docstring."""
    return decrypt_secret_with_key(ciphertext, current_encryption_key())


def encrypt_secret_with_key(plaintext: str, key: str) -> bytes:
    """`encrypt_secret` under an explicit `ENCRYPTION_KEY`-format key."""
    nonce = os.urandom(_NONCE_LENGTH)
    raw_key = base64.urlsafe_b64decode(key.encode("utf-8"))
    ciphertext = AESGCM(raw_key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return _AESGCM_VERSION + nonce + ciphertext


def decrypt_secret_with_key(ciphertext: bytes, key: str) -> str:
    """`decrypt_secret` under an explicit `ENCRYPTION_KEY`-format key."""
    if ciphertext[:1] == _AESGCM_VERSION:
        nonce = ciphertext[1 : 1 + _NONCE_LENGTH]
        body = ciphertext[1 + _NONCE_LENGTH :]
        raw_key = base64.urlsafe_b64decode(key.encode("utf-8"))
        try:
            return AESGCM(raw_key).decrypt(nonce, body, None).decode("utf-8")
        except InvalidTag as exc:
            raise DecryptionError("Failed to decrypt the stored secret.") from exc

    try:
        return Fernet(key.encode("utf-8")).decrypt(ciphertext).decode("utf-8")
    except InvalidToken as exc:
        raise DecryptionError("Failed to decrypt the stored secret.") from exc


def is_legacy_ciphertext(ciphertext: bytes) -> bool:
    """Whether `ciphertext` is still in the pre-AES-256 Fernet format.
    Used by `scripts/reencrypt_secrets.py` to find what's left to upgrade
    — not needed for normal `encrypt_secret`/`decrypt_secret` use."""
    return ciphertext[:1] != _AESGCM_VERSION
