#!/usr/bin/env python3
"""Recover a debcontrol account from the server console — no login required.

For when someone is locked out and can't get in through the web UI at all:
a forgotten password, a lost/broken TOTP device, or an account-level
lockout after too many failed attempts (including the account that would
normally reset everyone else's, if it's the one that's stuck). Deliberately
a console-only script, like `create_admin.py` — this is a "someone with
shell access on the server" capability, not a web feature, precisely
because it can bypass a locked account's own second factor.

Usage (inside the running `web` container):
    docker compose exec web python scripts/reset_account.py --username admin
    docker compose exec web python scripts/reset_account.py --username admin --disable-totp

Always: sets a new password (prompted interactively, or from
`DEBCONTROL_RESET_PASSWORD` for non-interactive/scripted use — see
`create_admin.py` for why an env var instead of a `--password` flag),
clears any lockout, resets the failed-attempt counter, and forces a
password change on next login. `--disable-totp` additionally turns off
two-factor and deletes its recovery codes — opt-in, since routine password
resets shouldn't silently strip 2FA off someone else's account.

Refuses to touch an LDAP/OIDC account's password (they don't have one to
reset here — see `app/db/models/user.py`), but `--disable-totp` still works
for an LDAP account (TOTP is supported for local and LDAP, just not OIDC).
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import os
import sys

from sqlalchemy import delete, select

from app.auth.security import hash_password
from app.db.models.totp_recovery_code import TotpRecoveryCode
from app.db.models.user import AuthProvider, User
from app.db.session import AsyncSessionLocal

_MIN_PASSWORD_LENGTH = 12


async def _reset_account(username: str, password: str | None, *, disable_totp: bool) -> None:
    username = username.strip().lower()

    async with AsyncSessionLocal() as db:
        result = await db.execute(select(User).where(User.username == username))
        user = result.scalar_one_or_none()
        if user is None:
            print(f'error: no user named "{username}".', file=sys.stderr)
            raise SystemExit(1)

        actions = []

        if password is not None:
            if user.auth_provider != AuthProvider.LOCAL:
                print(
                    f'error: "{username}" logs in via {user.auth_provider.value}, '
                    "not a local password — nothing to reset here.",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            if len(password) < _MIN_PASSWORD_LENGTH:
                print(
                    f"error: password must be at least {_MIN_PASSWORD_LENGTH} characters.",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            user.password_hash = hash_password(password)
            user.must_change_password = True
            actions.append("password reset")

        if disable_totp:
            if user.totp_enabled:
                user.totp_enabled = False
                user.totp_secret_encrypted = None
                user.totp_confirmed_at = None
                await db.execute(
                    delete(TotpRecoveryCode).where(TotpRecoveryCode.user_id == user.id)
                )
                actions.append("two-factor disabled")
            else:
                print(f'note: "{username}" didn\'t have two-factor enabled — nothing to disable.')

        was_locked = user.is_locked_out
        user.failed_login_attempts = 0
        user.locked_until = None
        if was_locked:
            actions.append("lockout cleared")

        if not actions:
            print(f'"{username}": nothing to do (no lockout, and no reset requested).')
            return

        await db.commit()

    print(f'"{username}": {", ".join(actions)}.')


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--username", required=True, help="The account to recover.")
    parser.add_argument(
        "--disable-totp",
        action="store_true",
        help="Also turn off two-factor authentication and delete its recovery codes.",
    )
    parser.add_argument(
        "--no-password",
        action="store_true",
        help="Don't touch the password — only clear lockout / disable TOTP.",
    )
    args = parser.parse_args()

    password: str | None = None
    if not args.no_password:
        password = os.environ.get("DEBCONTROL_RESET_PASSWORD")
        if not password:
            password = getpass.getpass("New password: ")
            if getpass.getpass("Confirm new password: ") != password:
                print("error: passwords didn't match.", file=sys.stderr)
                raise SystemExit(1)

    asyncio.run(_reset_account(args.username, password, disable_totp=args.disable_totp))


if __name__ == "__main__":
    main()
