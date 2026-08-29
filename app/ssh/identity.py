"""The application's shared SSH identity — see `app.db.models.ssh_identity`."""

from __future__ import annotations

from datetime import UTC, datetime

import asyncssh
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import encrypt_secret
from app.db.models.ssh_identity import SINGLETON_ID, SSHIdentity

_KEY_ALGORITHM = "ssh-ed25519"


def _generate_keypair() -> tuple[str, bytes, str]:
    """Returns (public_line, encrypted_private_pem, fingerprint)."""
    key = asyncssh.generate_private_key(_KEY_ALGORITHM, comment="debcontrol")
    private_pem = key.export_private_key().decode("ascii")
    public_line = key.export_public_key().decode("ascii").strip()
    fingerprint = key.get_fingerprint("sha256")
    return public_line, encrypt_secret(private_pem), fingerprint


async def get_or_create_identity(db: AsyncSession) -> SSHIdentity:
    """Return the app's SSH identity, generating it on first use.

    Generation races are possible (two requests hitting this at once before
    the row exists) — handled by catching the unique-key violation and
    re-reading, rather than locking.
    """
    identity = await db.get(SSHIdentity, SINGLETON_ID)
    if identity is not None:
        return identity

    public_line, private_encrypted, fingerprint = _generate_keypair()
    identity = SSHIdentity(
        id=SINGLETON_ID,
        public_key=public_line,
        private_key_encrypted=private_encrypted,
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


async def generate_pending_identity(db: AsyncSession) -> SSHIdentity:
    """Generate a replacement keypair into the `pending_*` columns,
    discarding any earlier not-yet-activated one. Doesn't touch the active
    key — see the module docstring on `app.db.models.ssh_identity` for why.
    """
    identity = await get_or_create_identity(db)
    public_line, private_encrypted, fingerprint = _generate_keypair()
    identity.pending_public_key = public_line
    identity.pending_private_key_encrypted = private_encrypted
    identity.pending_fingerprint = fingerprint
    identity.pending_generated_at = datetime.now(UTC)
    await db.commit()
    return identity


async def activate_pending_identity(db: AsyncSession) -> SSHIdentity:
    """Promote the pending key to active. The caller is responsible for
    having already confirmed it's deployed to every machine's
    `authorized_keys` — this doesn't check that, it just switches which key
    the app uses going forward."""
    identity = await get_or_create_identity(db)
    if identity.pending_public_key is None or identity.pending_private_key_encrypted is None:
        raise ValueError("No pending SSH key to activate.")
    identity.public_key = identity.pending_public_key
    identity.private_key_encrypted = identity.pending_private_key_encrypted
    identity.fingerprint = identity.pending_fingerprint or identity.fingerprint
    identity.pending_public_key = None
    identity.pending_private_key_encrypted = None
    identity.pending_fingerprint = None
    identity.pending_generated_at = None
    await db.commit()
    return identity


async def discard_pending_identity(db: AsyncSession) -> SSHIdentity:
    """Throw away a generated-but-not-activated pending key without
    switching anything — e.g. the operator changed their mind, or rolled
    out the wrong key by mistake and wants to start over."""
    identity = await get_or_create_identity(db)
    identity.pending_public_key = None
    identity.pending_private_key_encrypted = None
    identity.pending_fingerprint = None
    identity.pending_generated_at = None
    await db.commit()
    return identity
