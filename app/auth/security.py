"""Password hashing for local accounts — Argon2id via `argon2-cffi`, the
current OWASP-recommended default (memory-hard, tunable, better GPU/ASIC
resistance than bcrypt/PBKDF2).

Also used for TOTP recovery codes (`app.db.models.totp_recovery_code`) — a
recovery code is functionally a backup password, so it's hashed the same way.
"""

from __future__ import annotations

import re

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

_hasher = PasswordHasher()

# Login identifier: lowercase letters/digits plus `.`, `_`, `-`; must start
# with a letter or digit. This is also the LDAP bind username and (compared
# against a claim) the OIDC identity — restricting the character set avoids
# ever needing to worry about it inside an LDAP search filter or a URL, on
# top of `app.auth.ldap` filter-escaping it anyway as defense in depth.
USERNAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.-]{2,63}$")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """True if `password` matches `password_hash`. Never raises — an
    unrecognized/corrupted hash is treated as a non-match, not an error."""
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    """True if `password_hash` was made with weaker parameters than the
    hasher's current defaults — call after a successful `verify_password`
    and re-hash with `hash_password` if so, so hashes made under an older
    version of this app opportunistically get stronger over time."""
    return _hasher.check_needs_rehash(password_hash)
