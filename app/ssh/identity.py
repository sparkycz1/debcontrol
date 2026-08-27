"""The application's shared SSH identity — see `app.db.models.ssh_identity`."""

from __future__ import annotations

import asyncssh
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import encrypt_secret
from app.db.models.ssh_identity import SINGLETON_ID, SSHIdentity

_KEY_ALGORITHM = "ssh-ed25519"


async def get_or_create_identity(db: AsyncSession) -> SSHIdentity:
    """Return the app's SSH identity, generating it on first use.

    Generation races are possible (two requests hitting this at once before
    the row exists) — handled by catching the unique-key violation and
    re-reading, rather than locking.
    """
    identity = await db.get(SSHIdentity, SINGLETON_ID)
    if identity is not None:
        return identity

    key = asyncssh.generate_private_key(_KEY_ALGORITHM, comment="debcontrol")
    private_pem = key.export_private_key().decode("ascii")
    public_line = key.export_public_key().decode("ascii").strip()
    fingerprint = key.get_fingerprint("sha256")

    identity = SSHIdentity(
        id=SINGLETON_ID,
        public_key=public_line,
        private_key_encrypted=encrypt_secret(private_pem),
        fingerprint=fingerprint,
    )
    db.add(identity)
    try:
        await db.commit()
    except IntegrityError:
        # Another request created it concurrently — that's fine, use theirs.
        await db.rollback()
        identity = await db.get(SSHIdentity, SINGLETON_ID)
        assert identity is not None  # guaranteed by the unique violation above
    return identity
