"""The whole-application backup and restore against a real Postgres built by
`alembic upgrade head` — native enum types, TRUNCATE, sequence resets and
the `alembic_version` revision check, none of which the in-memory SQLite
suite exercises. Runs only when `TEST_POSTGRES_URL` is set (the CI
`postgres` job does); skipped everywhere else."""

from __future__ import annotations

import io
import os
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.app_settings import get_or_create_app_settings
from app.core.security import decrypt_secret, encrypt_secret
from app.db.models.machine import AuthMethod, Machine
from app.db.models.role import Permission, Role, RolePermission
from app.db.models.user import AuthProvider, User
from app.services import full_backup

POSTGRES_URL = os.environ.get("TEST_POSTGRES_URL")
pytestmark = pytest.mark.skipif(not POSTGRES_URL, reason="TEST_POSTGRES_URL not set")

PASSPHRASE = "correct horse battery"


@pytest_asyncio.fixture
async def pg() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    assert POSTGRES_URL
    engine = create_async_engine(POSTGRES_URL)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    yield factory
    await engine.dispose()


async def test_backup_and_restore_on_postgres(pg):
    async with pg() as db:
        await get_or_create_app_settings(db)
        role = Role(name="pg-admin")
        role.permission_grants = [RolePermission(permission=p) for p in Permission]
        db.add(role)
        await db.flush()
        db.add(User(username="pg-admin", auth_provider=AuthProvider.LOCAL, role=role))
        db.add(
            Machine(
                name="pg-kept",
                ip_address="10.1.1.1",
                port=22,
                username="root",
                auth_method=AuthMethod.PASSWORD,
                secret_encrypted=encrypt_secret("pg-secret"),
                disks=[{"name": "sda"}],
            )
        )
        await db.commit()

    sealed = io.BytesIO()
    async with pg() as db:
        manifest = await full_backup.write_backup(db, sealed, PASSPHRASE)
        revision = (await db.execute(text("SELECT version_num FROM alembic_version"))).scalar_one()
    assert manifest["database_revision"] == revision

    async with pg() as db:
        db.add(
            Machine(
                name="pg-added", ip_address="10.1.1.2", port=22, username="root",
                auth_method=AuthMethod.SSH_KEY,
            )
        )
        await db.commit()

    async with pg() as db:
        await full_backup.restore_backup(db, io.BytesIO(sealed.getvalue()), PASSPHRASE)

    async with pg() as db:
        machines = (await db.execute(select(Machine))).scalars().all()
        assert [m.name for m in machines] == ["pg-kept"]
        assert machines[0].auth_method is AuthMethod.PASSWORD
        assert machines[0].secret_encrypted is not None
        assert decrypt_secret(machines[0].secret_encrypted) == "pg-secret"
        assert machines[0].filesystems is None  # SQL NULL, not JSON null
        null_rows = await db.execute(
            text("SELECT count(*) FROM machines WHERE filesystems IS NULL")
        )
        assert null_rows.scalar_one() == 1
        assert (await db.execute(select(func.count()).select_from(User))).scalar_one() == 1
        # The restored instance keeps working: settings and new rows.
        await get_or_create_app_settings(db)
        db.add(
            Machine(
                name="pg-after", ip_address="10.1.1.3", port=22, username="root",
                auth_method=AuthMethod.SSH_KEY,
            )
        )
        await db.commit()
