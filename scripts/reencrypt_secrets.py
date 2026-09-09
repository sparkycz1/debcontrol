#!/usr/bin/env python3
"""Proactively upgrade every stored secret still in the legacy Fernet
(AES-128) format to the current AES-256-GCM one (`app.core.security`).

Optional — `decrypt_secret` already reads both formats transparently
forever, so nothing breaks by never running this. It exists for a
deployment that would rather not carry any AES-128 ciphertext at all going
forward, e.g. before a security review. Every value is re-encrypted under
the same `ENCRYPTION_KEY` (unchanged) — this is a format upgrade, not a
key rotation.

Usage (inside the running `web` container):
    docker compose exec web python scripts/reencrypt_secrets.py
    docker compose exec web python scripts/reencrypt_secrets.py --dry-run

Touches every `*_encrypted` column across the app: `Machine.secret_encrypted`,
`AiProviderConfig.api_key_encrypted`, `AppSettings.ldap_bind_password_encrypted`
/ `oidc_client_secret_encrypted`, `SSHIdentity.private_key_encrypted` /
`pending_private_key_encrypted`, `User.totp_secret_encrypted`. Idempotent —
running it again finds nothing left to do.
"""

from __future__ import annotations

import argparse
import asyncio
from collections.abc import Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import DecryptionError, decrypt_secret, encrypt_secret, is_legacy_ciphertext
from app.db.models.ai_provider import AiProviderConfig
from app.db.models.app_settings import AppSettings
from app.db.models.machine import Machine
from app.db.models.ssh_identity import SSHIdentity
from app.db.models.user import User
from app.db.session import AsyncSessionLocal

# (model, column name) pairs — every `*_encrypted` column in the app that
# goes through `app.core.security`.
_TARGETS: Sequence[tuple[type, str]] = (
    (Machine, "secret_encrypted"),
    (AiProviderConfig, "api_key_encrypted"),
    (AppSettings, "ldap_bind_password_encrypted"),
    (AppSettings, "oidc_client_secret_encrypted"),
    (SSHIdentity, "private_key_encrypted"),
    (SSHIdentity, "pending_private_key_encrypted"),
    (User, "totp_secret_encrypted"),
)


async def _reencrypt_column(
    db: AsyncSession, model: type, column_name: str, *, dry_run: bool
) -> tuple[int, int]:
    """Returns (upgraded, failed) counts for one column."""
    column = getattr(model, column_name)
    result = await db.execute(select(model).where(column.is_not(None)))
    upgraded = 0
    failed = 0
    for row in result.scalars().all():
        value: bytes | None = getattr(row, column_name)
        if value is None or not is_legacy_ciphertext(value):
            continue
        try:
            plaintext = decrypt_secret(value)
        except DecryptionError:
            label = getattr(row, "name", None) or getattr(row, "username", None) or row.id
            print(f"  ! {model.__name__}.{column_name} on {label!r}: couldn't decrypt, skipped")
            failed += 1
            continue
        if not dry_run:
            setattr(row, column_name, encrypt_secret(plaintext))
        upgraded += 1
    return upgraded, failed


async def _run(*, dry_run: bool) -> None:
    total_upgraded = 0
    total_failed = 0
    async with AsyncSessionLocal() as db:
        for model, column_name in _TARGETS:
            upgraded, failed = await _reencrypt_column(db, model, column_name, dry_run=dry_run)
            if upgraded or failed:
                verb = "would upgrade" if dry_run else "upgraded"
                print(f"{model.__name__}.{column_name}: {verb} {upgraded}, failed {failed}")
            total_upgraded += upgraded
            total_failed += failed
        if not dry_run:
            await db.commit()

    if total_upgraded == 0 and total_failed == 0:
        print("Nothing to do — every stored secret is already AES-256-GCM.")
        return
    if dry_run:
        print(f"\nDry run: would upgrade {total_upgraded} value(s), {total_failed} failure(s).")
    else:
        print(f"\nUpgraded {total_upgraded} value(s), {total_failed} failure(s).")
    if total_failed:
        print(
            "A failure almost always means ENCRYPTION_KEY here doesn't match the one that "
            "encrypted that value — investigate before assuming it's corrupt data."
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report what would change without writing anything.",
    )
    args = parser.parse_args()
    asyncio.run(_run(dry_run=args.dry_run))


if __name__ == "__main__":
    main()
