"""Scheduled full backups (`app.services.auto_backup`): when one is due,
what lands on the data volume and what is pruned, the failure path, and
the Backup & restore page and REST API around it."""

from __future__ import annotations

import io
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select

from app.core.app_settings import get_or_create_app_settings
from app.core.security import encrypt_secret
from app.db.models.app_settings import AppSettings
from app.db.models.audit_log import AuditLogEntry
from app.db.models.role import Permission
from app.services import auto_backup, full_backup
from app.tasks import jobs
from tests.test_api_v1_extended import _api_token

PASSPHRASE = "correct horse battery"


@pytest.fixture(autouse=True)
def _backup_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, db_session_factory: Any) -> Path:
    directory = tmp_path / "backups"
    monkeypatch.setattr(auto_backup, "backup_dir", lambda: directory)
    # The task opens its own session, as a worker would.
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    return directory


async def _enable(db_session_factory: Any, **values: Any) -> None:
    async with db_session_factory() as db:
        app_settings = await get_or_create_app_settings(db)
        app_settings.auto_backup_enabled = True
        app_settings.auto_backup_passphrase_encrypted = encrypt_secret(PASSPHRASE)
        for key, value in values.items():
            setattr(app_settings, key, value)
        await db.commit()


def _seed_old_backups(directory: Path) -> None:
    directory.mkdir()
    for stamp in ("20260101T000000Z", "20260102T000000Z", "20260103T000000Z"):
        (directory / f"debcontrol-backup-{stamp}.dcbak").write_bytes(b"old")


def test_is_due_needs_the_switch_a_passphrase_and_the_interval() -> None:
    now = datetime(2026, 10, 4, 12, 0, tzinfo=UTC)
    settings = AppSettings(
        auto_backup_enabled=False,
        auto_backup_interval_hours=24,
        auto_backup_passphrase_encrypted=b"x",
    )
    assert not auto_backup.is_due(settings, now)
    settings.auto_backup_enabled = True
    assert auto_backup.is_due(settings, now)
    settings.auto_backup_last_at = now - timedelta(hours=23)
    assert not auto_backup.is_due(settings, now)
    settings.auto_backup_last_at = now - timedelta(hours=24)
    assert auto_backup.is_due(settings, now)
    settings.auto_backup_passphrase_encrypted = None
    assert not auto_backup.is_due(settings, now)


def test_only_real_backup_names_are_served(_backup_dir: Path) -> None:
    _backup_dir.mkdir()
    good = "debcontrol-backup-20261004T120000Z.dcbak"
    (_backup_dir / good).write_bytes(b"x")
    (_backup_dir / "notes.txt").write_bytes(b"x")
    (_backup_dir / f"{good}.part").write_bytes(b"x")

    assert [b.name for b in auto_backup.list_backups()] == [good]
    assert auto_backup.backup_path(good) is not None
    for name in ("notes.txt", "../secret", f"{good}.part", "debcontrol-backup-x.dcbak"):
        assert auto_backup.backup_path(name) is None
        assert not auto_backup.delete_backup(name)


async def test_due_backup_is_written_restorable_and_old_ones_pruned(
    db_session_factory: Any, _backup_dir: Path
) -> None:
    await _enable(db_session_factory, auto_backup_keep=2)
    _seed_old_backups(_backup_dir)

    result = await jobs._run_due_app_backup()
    assert result["ok"] and result["file"]

    names = [b.name for b in auto_backup.list_backups()]
    assert names == [result["file"], "debcontrol-backup-20260103T000000Z.dcbak"]
    # The stored file is a real backup under the stored passphrase.
    plain = io.BytesIO()
    with (_backup_dir / result["file"]).open("rb") as source:
        full_backup._decrypt_file(source, plain, PASSPHRASE)
    assert plain.getvalue()

    async with db_session_factory() as db:
        app_settings = await get_or_create_app_settings(db)
        assert app_settings.auto_backup_last_at is not None
        assert app_settings.auto_backup_last_error is None
        actions = (await db.execute(select(AuditLogEntry.action))).scalars().all()
    assert "backup.auto.run" in actions

    # Not due again right away.
    assert (await jobs._run_due_app_backup()) == {"ok": True, "skipped": True}


async def test_nothing_runs_while_switched_off(db_session_factory: Any, _backup_dir: Path) -> None:
    assert (await jobs._run_due_app_backup()) == {"ok": True, "skipped": True}
    assert auto_backup.list_backups() == []


async def test_a_failed_backup_is_recorded_and_notified(
    db_session_factory: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    await _enable(db_session_factory)
    notified: list[Any] = []

    async def _boom(*args: Any, **kwargs: Any) -> None:
        raise OSError("disk full")

    async def _notify(db: Any, event_type: Any, **kwargs: Any) -> None:
        notified.append((event_type.value, kwargs["context"]["details"]))

    monkeypatch.setattr(full_backup, "write_backup", _boom)
    monkeypatch.setattr(jobs, "notify", _notify)

    result = await jobs._run_due_app_backup()

    assert result == {"ok": False, "error": "disk full", "file": None}
    assert notified == [("app.backup_failed", "disk full")]
    assert auto_backup.list_backups() == []
    async with db_session_factory() as db:
        app_settings = await get_or_create_app_settings(db)
        assert app_settings.auto_backup_last_error == "disk full"


async def test_web_settings_list_download_and_delete(
    client: Any, db_session_factory: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    queued: list[bool] = []
    monkeypatch.setattr(jobs.run_due_app_backup, "delay", lambda force: queued.append(force))

    page = await client.get("/backup")
    assert 'action="/backup/auto"' in page.text
    csrf = {"csrf_token": client.cookies.get("csrftoken")}

    # Switching it on needs a passphrase.
    refused = await client.post("/backup/auto", data={**csrf, "enabled": "on"})
    assert refused.status_code == 422
    saved = await client.post(
        "/backup/auto",
        data={
            **csrf,
            "enabled": "on",
            "interval_hours": "12",
            "keep": "3",
            "passphrase": PASSPHRASE,
        },
        follow_redirects=False,
    )
    assert saved.status_code == 303
    async with db_session_factory() as db:
        app_settings = await get_or_create_app_settings(db)
        assert app_settings.auto_backup_enabled
        assert (app_settings.auto_backup_interval_hours, app_settings.auto_backup_keep) == (12, 3)

    started = await client.post("/backup/auto/run", data=csrf, follow_redirects=False)
    assert started.status_code == 303 and queued == [True]

    await jobs._run_due_app_backup(force=True)
    name = auto_backup.list_backups()[0].name
    assert name in (await client.get("/backup")).text

    download = await client.get(f"/backup/auto/files/{name}")
    assert download.status_code == 200
    assert download.content.startswith(full_backup.MAGIC)
    assert (await client.get("/backup/auto/files/nope.dcbak")).status_code == 404

    deleted = await client.post(
        f"/backup/auto/files/{name}/delete", data=csrf, follow_redirects=False
    )
    assert deleted.status_code == 303
    assert auto_backup.list_backups() == []


async def test_stored_backups_need_every_permission(client: Any, login_as: Any) -> None:
    await login_as(client, permissions=set(Permission) - {Permission.USER_IMPERSONATE})
    page = await client.get("/backup")
    assert 'action="/backup/auto"' not in page.text
    csrf = {"csrf_token": client.cookies.get("csrftoken")}
    assert (await client.post("/backup/auto", data=csrf)).status_code == 403
    assert (await client.post("/backup/auto/run", data=csrf)).status_code == 403
    name = "debcontrol-backup-20261004T120000Z.dcbak"
    assert (await client.get(f"/backup/auto/files/{name}")).status_code == 403


async def test_api_auto_backup(
    client: Any, db_session_factory: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    queued: list[bool] = []
    monkeypatch.setattr(jobs.run_due_app_backup, "delay", lambda force: queued.append(force))
    headers = await _api_token(client)

    initial = (await client.get("/api/v1/backup/auto", headers=headers)).json()
    assert initial["enabled"] is False and initial["passphrase_set"] is False

    body = {"enabled": True, "interval_hours": 6, "keep": 4}
    assert (await client.put("/api/v1/backup/auto", json=body, headers=headers)).status_code == 422
    updated = await client.put(
        "/api/v1/backup/auto", json={**body, "passphrase": PASSPHRASE}, headers=headers
    )
    assert updated.status_code == 200
    assert updated.json()["passphrase_set"] is True
    assert "passphrase" not in updated.json()

    run = await client.post("/api/v1/backup/auto/run", headers=headers)
    assert run.status_code == 202 and queued == [True]

    await jobs._run_due_app_backup(force=True)
    listed = (await client.get("/api/v1/backup/auto", headers=headers)).json()
    name = listed["backups"][0]["name"]
    file = await client.get(f"/api/v1/backup/auto/files/{name}", headers=headers)
    assert file.content.startswith(full_backup.MAGIC)
    assert (
        await client.delete(f"/api/v1/backup/auto/files/{name}", headers=headers)
    ).status_code == 204
    assert (
        await client.delete(f"/api/v1/backup/auto/files/{name}", headers=headers)
    ).status_code == 404
