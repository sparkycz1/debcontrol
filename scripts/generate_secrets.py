#!/usr/bin/env python3
"""Vygeneruje bezpečné náhodné hodnoty pro `.env` (SECRET_KEY, ENCRYPTION_KEY, hesla).

Použití:
    python scripts/generate_secrets.py

Vypíše hotové řádky k vložení do `.env` — nikam je needitujte automaticky,
ať máte kontrolu nad tím, co se přepíše.
"""

from __future__ import annotations

import secrets

from cryptography.fernet import Fernet


def main() -> None:
    print(f"SECRET_KEY={secrets.token_urlsafe(64)}")
    print(f"ENCRYPTION_KEY={Fernet.generate_key().decode()}")
    print(f"POSTGRES_PASSWORD={secrets.token_urlsafe(24)}")
    print(f"REDIS_PASSWORD={secrets.token_urlsafe(24)}")


if __name__ == "__main__":
    main()
