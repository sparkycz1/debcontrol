"""Resolve the credential material to authenticate a machine's SSH connection."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import decrypt_secret
from app.db.models.machine import AuthMethod, Machine
from app.ssh.identity import get_or_create_identity


async def resolve_machine_credential(machine: Machine, db: AsyncSession) -> str | None:
    """Return the secret to pass to `app.ssh.client.open_connection`.

    For `AuthMethod.SSH_KEY` (the default), that's the app's own shared
    private key (decrypted on the fly, never written to disk). For
    `AuthMethod.PASSWORD`, it's whatever password is stored on the machine
    itself, if any.
    """
    if machine.auth_method == AuthMethod.PASSWORD:
        return decrypt_secret(machine.secret_encrypted) if machine.secret_encrypted else None

    identity = await get_or_create_identity(db)
    return decrypt_secret(identity.private_key_encrypted)
