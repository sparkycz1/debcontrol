#!/usr/bin/env python3
"""Generate secure random values for `.env` (SECRET_KEY, ENCRYPTION_KEY, passwords).

Usage:
    python3 scripts/generate_secrets.py

Prints ready-to-paste lines for `.env` — it never edits the file for you,
so you stay in control of what gets overwritten. Part of the manual setup
path (see wiki/Installation); `scripts/setup.py` does this step for you
automatically as part of an interactive, end-to-end setup wizard.
"""

from __future__ import annotations

import secrets

from cryptography.fernet import Fernet


def main() -> None:
    print(f"SECRET_KEY={secrets.token_urlsafe(64)}")
    print(f"ENCRYPTION_KEY={Fernet.generate_key().decode()}")
    print(f"POSTGRES_PASSWORD={secrets.token_urlsafe(24)}")
    print(f"REDIS_PASSWORD={secrets.token_urlsafe(24)}")
    print(f"INFORM_TOKEN={secrets.token_urlsafe(32)}")


if __name__ == "__main__":
    main()
