from __future__ import annotations

from app.ssh.identity import get_or_create_identity


async def test_get_or_create_identity_is_idempotent(db_session_factory):
    async with db_session_factory() as session:
        first = await get_or_create_identity(session)

    assert first.public_key.startswith("ssh-ed25519 ")
    assert first.fingerprint.startswith("SHA256:")

    async with db_session_factory() as session:
        second = await get_or_create_identity(session)

    assert second.id == first.id
    assert second.public_key == first.public_key
    assert second.fingerprint == first.fingerprint
