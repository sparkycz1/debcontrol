"""The whole-application backup and restore (`app.services.full_backup`,
Backup & restore → "Whole application", `POST /api/v1/backup`)."""

from __future__ import annotations

import base64
import io
import os

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.security import (
    current_encryption_key,
    decrypt_secret,
    decrypt_secret_with_key,
    encrypt_secret,
)
from app.db.models.machine import AuthMethod, Machine
from app.db.models.role import Permission
from app.services import full_backup
from tests.test_api_v1_extended import _api_token

PASSPHRASE = "correct horse battery"


def test_encrypted_file_round_trips_and_refuses_a_wrong_passphrase():
    payload = os.urandom(3 * 1024 * 1024 + 17)  # several chunks
    sealed = io.BytesIO()
    full_backup._encrypt_file(io.BytesIO(payload), sealed, PASSPHRASE)

    opened = io.BytesIO()
    full_backup._decrypt_file(io.BytesIO(sealed.getvalue()), opened, PASSPHRASE)
    assert opened.getvalue() == payload

    with pytest.raises(full_backup.BackupError, match="Wrong passphrase"):
        full_backup._decrypt_file(io.BytesIO(sealed.getvalue()), io.BytesIO(), "not it at all")


def test_a_truncated_or_foreign_file_is_refused():
    sealed = io.BytesIO()
    full_backup._encrypt_file(io.BytesIO(os.urandom(2 * 1024 * 1024)), sealed, PASSPHRASE)
    data = sealed.getvalue()

    with pytest.raises(full_backup.BackupError, match="truncated"):
        full_backup._decrypt_file(io.BytesIO(data[: len(data) // 2]), io.BytesIO(), PASSPHRASE)
    with pytest.raises(full_backup.BackupError, match="isn't a debcontrol"):
        full_backup._decrypt_file(io.BytesIO(b"PK\x03\x04 a zip"), io.BytesIO(), PASSPHRASE)


async def _add_machine(
    db_session_factory: async_sessionmaker[AsyncSession], name: str, secret: str
) -> None:
    async with db_session_factory() as db:
        db.add(
            Machine(
                name=name,
                ip_address="10.0.0.9",
                port=22,
                username="root",
                auth_method=AuthMethod.PASSWORD,
                secret_encrypted=encrypt_secret(secret),
                disks=[{"name": "sda"}],
            )
        )
        await db.commit()


async def _machine_names(db_session_factory: async_sessionmaker[AsyncSession]) -> list[str]:
    async with db_session_factory() as db:
        return sorted((await db.execute(select(Machine.name))).scalars().all())


async def test_restore_puts_back_exactly_what_was_backed_up(db_session_factory):
    await _add_machine(db_session_factory, "kept", "s3cret")
    sealed = io.BytesIO()
    async with db_session_factory() as db:
        manifest = await full_backup.write_backup(db, sealed, PASSPHRASE)
    assert manifest["tables"]["machines"] == 1
    assert "encryption_key" not in manifest

    await _add_machine(db_session_factory, "added-later", "x")
    async with db_session_factory() as db:
        restored = await full_backup.restore_backup(
            db, io.BytesIO(sealed.getvalue()), PASSPHRASE
        )

    assert restored["app"] == "debcontrol"
    assert await _machine_names(db_session_factory) == ["kept"]
    async with db_session_factory() as db:
        machine = (await db.execute(select(Machine))).scalar_one()
        assert machine.secret_encrypted is not None
        assert decrypt_secret(machine.secret_encrypted) == "s3cret"
        assert machine.disks == [{"name": "sda"}]
        assert machine.filesystems is None


async def test_secrets_are_re_encrypted_for_an_instance_with_another_key(
    db_session_factory, monkeypatch
):
    await _add_machine(db_session_factory, "moved", "s3cret")
    sealed = io.BytesIO()
    async with db_session_factory() as db:
        await full_backup.write_backup(db, sealed, PASSPHRASE)

    other_key = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")
    assert other_key != current_encryption_key()
    monkeypatch.setattr(full_backup, "current_encryption_key", lambda: other_key)
    async with db_session_factory() as db:
        await full_backup.restore_backup(db, io.BytesIO(sealed.getvalue()), PASSPHRASE)

    async with db_session_factory() as db:
        machine = (await db.execute(select(Machine))).scalar_one()
        assert machine.secret_encrypted is not None
        assert decrypt_secret_with_key(machine.secret_encrypted, other_key) == "s3cret"


async def test_a_backup_from_another_database_revision_is_refused(
    db_session_factory, monkeypatch
):
    async def _revision(db):
        return "aaaa"

    monkeypatch.setattr(full_backup, "_database_revision", _revision)
    sealed = io.BytesIO()
    async with db_session_factory() as db:
        await full_backup.write_backup(db, sealed, PASSPHRASE)

    async def _other_revision(db):
        return "bbbb"

    monkeypatch.setattr(full_backup, "_database_revision", _other_revision)
    async with db_session_factory() as db:
        with pytest.raises(full_backup.BackupError, match="same version"):
            await full_backup.restore_backup(db, io.BytesIO(sealed.getvalue()), PASSPHRASE)


async def test_web_download_and_restore(client, db_session_factory):
    await _add_machine(db_session_factory, "web-kept", "pw")
    page = await client.get("/backup")
    assert 'action="/backup/full"' in page.text

    download = await client.post(
        "/backup/full",
        data={
            "csrf_token": client.cookies.get("csrftoken"),
            "passphrase": PASSPHRASE,
            "passphrase_confirm": PASSPHRASE,
        },
    )
    assert download.status_code == 200
    assert download.content.startswith(full_backup.MAGIC)
    assert ".dcbak" in download.headers["content-disposition"]

    await _add_machine(db_session_factory, "web-added", "pw")
    wrong = await client.post(
        "/backup/full/restore",
        data={"csrf_token": client.cookies.get("csrftoken"), "passphrase": "nope-nope-nope",
              "confirm": "RESTORE"},
        files={"backup_file": ("b.dcbak", download.content, "application/octet-stream")},
    )
    assert wrong.status_code == 422
    assert "Wrong passphrase" in wrong.text
    assert await _machine_names(db_session_factory) == ["web-added", "web-kept"]

    restored = await client.post(
        "/backup/full/restore",
        data={"csrf_token": client.cookies.get("csrftoken"), "passphrase": PASSPHRASE,
              "confirm": "RESTORE"},
        files={"backup_file": ("b.dcbak", download.content, "application/octet-stream")},
        follow_redirects=False,
    )
    assert restored.status_code == 303
    assert restored.headers["location"].startswith("/login?notice=")
    assert await _machine_names(db_session_factory) == ["web-kept"]


async def test_restore_needs_the_typed_confirmation(client):
    await client.get("/backup")
    response = await client.post(
        "/backup/full/restore",
        data={"csrf_token": client.cookies.get("csrftoken"), "passphrase": PASSPHRASE,
              "confirm": "yes"},
        files={"backup_file": ("b.dcbak", b"whatever", "application/octet-stream")},
    )
    assert response.status_code == 422
    assert "RESTORE" in response.text


async def test_mismatched_passphrases_are_refused(client):
    await client.get("/backup")
    response = await client.post(
        "/backup/full",
        data={"csrf_token": client.cookies.get("csrftoken"), "passphrase": PASSPHRASE,
              "passphrase_confirm": PASSPHRASE + "!"},
    )
    assert response.status_code == 422


async def test_only_an_account_with_every_permission_gets_the_full_backup(client, login_as):
    await login_as(client, permissions=set(Permission) - {Permission.USER_IMPERSONATE})
    page = await client.get("/backup")
    assert 'action="/backup/full"' not in page.text

    response = await client.post(
        "/backup/full",
        data={"csrf_token": client.cookies.get("csrftoken"), "passphrase": PASSPHRASE,
              "passphrase_confirm": PASSPHRASE},
    )
    assert response.status_code == 403


async def test_api_full_backup(client):
    headers = await _api_token(client)
    response = await client.post(
        "/api/v1/backup", json={"passphrase": PASSPHRASE}, headers=headers
    )
    assert response.status_code == 200
    assert response.content.startswith(full_backup.MAGIC)

    short = await client.post("/api/v1/backup", json={"passphrase": "short"}, headers=headers)
    assert short.status_code == 422
