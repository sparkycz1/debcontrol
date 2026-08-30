#!/usr/bin/env python3
"""Bootstrap the very first Administrator account.

Every debcontrol account is created inside the app itself (see
`app/db/models/user.py` — no auto-provisioning from LDAP/OIDC), and every
page now requires a login (see `app.auth.middleware`) — so a fresh
deployment needs one way in that isn't a web page. This is it.

Usage (inside the running `web` container):
    docker compose exec web python scripts/create_admin.py --username admin

Prompts for a password interactively. For non-interactive/scripted use, set
`DEBCONTROL_ADMIN_PASSWORD` in the environment instead of a `--password`
flag — a flag would show up in `docker compose exec`'s process listing, an
environment variable doesn't.

Reuses an existing "Administrator" role (creating one with every permission
if it doesn't exist yet) rather than creating a duplicate each time this is
run. Refuses to run if the username already exists — use the Users page (or
another admin account) to manage it from there on.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import os
import sys

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.security import USERNAME_PATTERN, hash_password
from app.db.models.role import Permission, Role, RolePermission
from app.db.models.user import AuthProvider, User
from app.db.session import AsyncSessionLocal

_ADMIN_ROLE_NAME = "Administrator"
_MIN_PASSWORD_LENGTH = 12


async def _get_or_create_admin_role(db: AsyncSession) -> Role:
    result = await db.execute(select(Role).where(Role.name == _ADMIN_ROLE_NAME))
    role = result.scalar_one_or_none()
    if role is None:
        role = Role(
            name=_ADMIN_ROLE_NAME,
            description="Full access to everything, including user and role management.",
        )
        role.permission_grants = [RolePermission(permission=p) for p in Permission]
        db.add(role)
        await db.flush()
        return role

    # Top up rather than just reusing as-is: this role was created at some
    # earlier point in time from whatever `Permission` values existed then.
    # If the app has since gained a new permission (e.g. `action.terminal`
    # for the SSH terminal), an "Administrator" role from before that point
    # would otherwise silently keep missing it forever — contradicting its
    # own "Full access to everything" description — since nothing else ever
    # re-syncs an existing role's permissions against the current enum.
    granted = {grant.permission for grant in role.permission_grants}
    missing = [p for p in Permission if p not in granted]
    if missing:
        role.permission_grants.extend(RolePermission(permission=p) for p in missing)
        await db.flush()
    return role


async def _create_admin(username: str, password: str) -> None:
    username = username.strip().lower()
    if not USERNAME_PATTERN.match(username):
        print(
            f'error: "{username}" isn\'t a valid username '
            "(3-64 chars: lowercase letters, digits, '.', '_', '-').",
            file=sys.stderr,
        )
        raise SystemExit(1)
    if len(password) < _MIN_PASSWORD_LENGTH:
        print(
            f"error: password must be at least {_MIN_PASSWORD_LENGTH} characters.", file=sys.stderr
        )
        raise SystemExit(1)

    async with AsyncSessionLocal() as db:
        existing = await db.execute(select(User).where(User.username == username))
        if existing.scalar_one_or_none() is not None:
            print(f'error: a user named "{username}" already exists.', file=sys.stderr)
            raise SystemExit(1)

        role = await _get_or_create_admin_role(db)
        user = User(
            username=username,
            auth_provider=AuthProvider.LOCAL,
            password_hash=hash_password(password),
            must_change_password=True,
            role=role,
        )
        db.add(user)
        await db.commit()

    print(
        f'Created "{username}" with the "{_ADMIN_ROLE_NAME}" role. '
        "They'll be asked to change this password on first login."
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--username", required=True, help="Login name for the new administrator.")
    args = parser.parse_args()

    password = os.environ.get("DEBCONTROL_ADMIN_PASSWORD")
    if not password:
        password = getpass.getpass("Password: ")
        if getpass.getpass("Confirm password: ") != password:
            print("error: passwords didn't match.", file=sys.stderr)
            raise SystemExit(1)

    asyncio.run(_create_admin(args.username, password))


if __name__ == "__main__":
    main()
