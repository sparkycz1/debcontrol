"""REST API of the Docker tab: restic backups and the container / volume
file browser (`app/web/routes/api_v1_docker.py`)."""

from __future__ import annotations

import base64
import uuid
from typing import Any

from sqlalchemy import select, update

from app.core.security import decrypt_secret
from app.db.models.audit_log import AuditLogEntry
from app.db.models.docker import DockerBackup, DockerJob, DockerJobStatus
from app.db.models.role import Permission
from app.services import docker_jobs
from tests.test_api_v1_docker import audit_actions, base, docker_machine, headers_for
from tests.test_api_v1_extended import _api_token

REPOSITORY = "rest:https://backupuser:repo-pass-secret@backup.example.com:8000/shop"
PASSWORD = "restic-password-secret"
ENV = "AWS_SECRET_ACCESS_KEY=env-secret-value"
SNAPSHOTS = "app.tasks.docker_jobs.docker_backup_snapshots"
FILES = "app.tasks.docker_jobs.docker_files"
SECRETS = ("repo-pass-secret", "backupuser", PASSWORD, "env-secret-value")


def backup_payload(**extra: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "name": "nightly",
        "repository": REPOSITORY,
        "password": PASSWORD,
        "env": ENV,
        "volumes": ["shop_data"],
        "paths": ["/srv/shop"],
        "keep_daily": 7,
    }
    payload.update(extra)
    return payload


async def create_backup(client: Any, machine_id: str, headers: dict[str, str], **extra: Any) -> Any:
    return await client.post(
        f"{base(machine_id)}/backups", json=backup_payload(**extra), headers=headers
    )


def assert_no_secrets(text: str) -> None:
    for secret in SECRETS:
        assert secret not in text, secret


async def finish_jobs(db_session_factory: Any) -> None:
    async with db_session_factory() as session:
        await session.execute(update(DockerJob).values(status=DockerJobStatus.SUCCEEDED))
        await session.commit()


# --- Backups ------------------------------------------------------------------------


async def test_backup_create_never_returns_secrets(client, login_as, db_session_factory):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)

    created = await create_backup(client, machine_id, headers)
    assert created.status_code == 201, created.text
    assert_no_secrets(created.text)
    body = created.json()
    assert body["repository"] == "rest:https://***@backup.example.com:8000/shop"
    assert body["volumes"] == ["shop_data"]
    assert body["paths"] == ["/srv/shop"]
    assert body["keep_daily"] == 7
    assert "password" not in body
    assert "env" not in body
    assert ("machine.docker.backup.create", "success") in await audit_actions(db_session_factory)

    async with db_session_factory() as session:
        row = (await session.execute(select(DockerBackup))).scalar_one()
        assert decrypt_secret(row.password_encrypted) == PASSWORD
        assert decrypt_secret(row.repository_encrypted) == REPOSITORY
        details = [str(d) for d in (await session.execute(select(AuditLogEntry.details))).scalars()]
    assert_no_secrets(" ".join(details))

    backup_id = body["id"]
    for response in (
        await client.get(f"{base(machine_id)}/backups", headers=headers),
        await client.get(f"{base(machine_id)}/backups/{backup_id}", headers=headers),
    ):
        assert response.status_code == 200
        assert_no_secrets(response.text)

    viewer = await headers_for(client, login_as, {Permission.MACHINE_VIEW})
    listed = await client.get(f"{base(machine_id)}/backups", headers=viewer)
    assert listed.status_code == 200
    assert [b["name"] for b in listed.json()] == ["nightly"]


async def test_backup_create_validation(client, db_session_factory):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)

    def detail(response: Any) -> list[str]:
        assert response.status_code == 422, response.text
        return list(response.json()["detail"])

    assert "docker.backup.error.password" in detail(
        await create_backup(client, machine_id, headers, password="")
    )
    assert "docker.backup.error.repository" in detail(
        await create_backup(client, machine_id, headers, repository="ftp://nope")
    )
    assert "docker.backup.error.nothing" in detail(
        await create_backup(client, machine_id, headers, volumes=[], paths=[])
    )
    assert "docker.backup.error.paths" in detail(
        await create_backup(client, machine_id, headers, paths=["/proc"])
    )
    assert "docker.backup.error.keep" in detail(
        await create_backup(client, machine_id, headers, keep_daily=0)
    )
    assert "docker.backup.error.volumes" in detail(
        await create_backup(client, machine_id, headers, volumes=["bad volume"])
    )
    # Pydantic-level: missing name, too long, wrong types.
    missing_name = await client.post(
        f"{base(machine_id)}/backups",
        json={k: v for k, v in backup_payload().items() if k != "name"},
        headers=headers,
    )
    assert missing_name.status_code == 422
    assert (await create_backup(client, machine_id, headers, name="n" * 65)).status_code == 422
    assert (await create_backup(client, machine_id, headers, volumes="x")).status_code == 422

    assert (await create_backup(client, machine_id, headers)).status_code == 201
    assert "docker.backup.error.name_taken" in detail(
        await create_backup(client, machine_id, headers)
    )


async def test_backup_edit_keeps_secrets_when_empty(client, db_session_factory):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)
    backup_id = (await create_backup(client, machine_id, headers)).json()["id"]
    other_id = (await create_backup(client, machine_id, headers, name="weekly")).json()["id"]
    url = f"{base(machine_id)}/backups/{backup_id}"

    saved = await client.put(
        url,
        json={"name": "nightly2", "volumes": ["shop_data", "shop_db"], "keep_last": 3},
        headers=headers,
    )
    assert saved.status_code == 200, saved.text
    assert_no_secrets(saved.text)
    body = saved.json()
    assert body["name"] == "nightly2"
    assert body["volumes"] == ["shop_data", "shop_db"]
    assert body["paths"] == []
    assert body["keep_last"] == 3
    assert body["keep_daily"] is None
    assert body["repository"].startswith("rest:https://***@")

    async with db_session_factory() as session:
        row = await session.get(DockerBackup, uuid.UUID(backup_id))
        assert row is not None
        assert decrypt_secret(row.password_encrypted) == PASSWORD
        assert decrypt_secret(row.repository_encrypted) == REPOSITORY
        assert row.env_encrypted is not None
        assert decrypt_secret(row.env_encrypted) == ENV

    taken = await client.put(
        f"{base(machine_id)}/backups/{other_id}",
        json={"name": "nightly2", "volumes": ["x"]},
        headers=headers,
    )
    assert taken.status_code == 422
    assert "docker.backup.error.name_taken" in taken.json()["detail"]
    assert ("machine.docker.backup.edit", "success") in await audit_actions(db_session_factory)


async def test_backup_write_permissions(client, login_as, db_session_factory):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)
    backup_id = (await create_backup(client, machine_id, headers)).json()["id"]
    url = f"{base(machine_id)}/backups/{backup_id}"

    updates = await headers_for(
        client, login_as, {Permission.MACHINE_VIEW, Permission.ACTION_UPDATES}, username="dk-up"
    )
    assert (await create_backup(client, machine_id, updates, name="x")).status_code == 403
    assert (await client.put(url, json={"name": "x"}, headers=updates)).status_code == 403
    deleted = await client.delete(url, headers=updates)
    assert deleted.status_code == 403
    restore = await client.post(
        f"{url}/restore", json={"snapshot": "latest", "confirm": "dock"}, headers=updates
    )
    assert restore.status_code == 403
    # Running a backup is action.updates.
    assert (await client.post(f"{url}/run", headers=updates)).status_code == 202

    terminal = await headers_for(client, login_as, {Permission.ACTION_TERMINAL}, username="dk-term")
    for what in ("run", "check", "forget"):
        assert (await client.post(f"{url}/{what}", headers=terminal)).status_code == 403

    viewer = await headers_for(client, login_as, {Permission.MACHINE_VIEW}, username="dk-view")
    assert (await client.get(url, headers=viewer)).status_code == 200
    assert (await client.post(f"{url}/check", headers=viewer)).status_code == 403


async def test_backup_jobs(client, db_session_factory):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)
    backup_id = (await create_backup(client, machine_id, headers)).json()["id"]
    no_retention = (
        await create_backup(client, machine_id, headers, name="forever", keep_daily=None)
    ).json()["id"]
    url = f"{base(machine_id)}/backups/{backup_id}"

    run = await client.post(f"{url}/run", headers=headers)
    assert run.status_code == 202, run.text
    assert run.json()["job"]["kind"] == "backup_run"
    assert (await client.post(f"{url}/run", headers=headers)).status_code == 409
    assert ("machine.docker.backup.run", "success") in await audit_actions(db_session_factory)

    check = await client.post(f"{url}/check", json={"read_data_percent": 10}, headers=headers)
    assert check.status_code == 202
    assert check.json()["job"]["params"] == {"read_data_percent": 10}
    over = await client.post(f"{url}/check", json={"read_data_percent": 101}, headers=headers)
    assert over.status_code == 422

    forget = await client.post(f"{url}/forget", headers=headers)
    assert forget.status_code == 202
    refused = await client.post(
        f"{base(machine_id)}/backups/{no_retention}/forget", headers=headers
    )
    assert refused.status_code == 400

    assert (await client.post(f"{url}/explode", headers=headers)).status_code == 422

    detail = await client.get(url, headers=headers)
    assert {j["kind"] for j in detail.json()["jobs"]} == {
        "backup_run",
        "backup_check",
        "backup_forget",
    }


async def test_backup_run_protected_volumes(client, db_session_factory, monkeypatch):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)
    backup_id = (
        await create_backup(
            client, machine_id, headers, volumes=["debcontrol_pgdata"], stop_containers=True
        )
    ).json()["id"]

    async def _protected(db: Any, machine: Any) -> str:
        return "debcontrol"

    monkeypatch.setattr(docker_jobs, "protected_project", _protected)
    response = await client.post(f"{base(machine_id)}/backups/{backup_id}/run", headers=headers)
    assert response.status_code == 409


async def test_backup_jobs_need_host_key(client, db_session_factory):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers, ready=False)
    backup_id = (await create_backup(client, machine_id, headers)).json()["id"]
    response = await client.post(f"{base(machine_id)}/backups/{backup_id}/run", headers=headers)
    assert response.status_code == 400


async def test_backup_restore_confirm(client, db_session_factory, monkeypatch):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers, name="dock-r")
    backup_id = (await create_backup(client, machine_id, headers)).json()["id"]
    url = f"{base(machine_id)}/backups/{backup_id}/restore"

    unconfirmed = await client.post(url, json={"snapshot": "latest"}, headers=headers)
    assert unconfirmed.status_code == 400
    wrong = await client.post(url, json={"snapshot": "latest", "confirm": "dock"}, headers=headers)
    assert wrong.status_code == 400
    assert ("machine.docker.backup.restore", "denied") in await audit_actions(db_session_factory)

    bad_snapshot = await client.post(
        url, json={"snapshot": "../../x", "confirm": "dock-r"}, headers=headers
    )
    assert bad_snapshot.status_code == 400
    nothing = await client.post(
        url,
        json={"snapshot": "latest", "confirm": "dock-r", "volumes": ["other"], "paths": []},
        headers=headers,
    )
    assert nothing.status_code == 400
    missing_snapshot = await client.post(url, json={"confirm": "dock-r"}, headers=headers)
    assert missing_snapshot.status_code == 422

    ok = await client.post(
        url,
        json={"snapshot": "0123abcd", "confirm": "dock-r", "volumes": ["shop_data"], "paths": []},
        headers=headers,
    )
    assert ok.status_code == 202, ok.text
    assert ok.json()["job"]["params"] == {
        "snapshot": "0123abcd",
        "volumes": ["shop_data"],
        "paths": [],
        "delete": False,
    }
    assert_no_secrets(ok.text)
    await finish_jobs(db_session_factory)

    everything = await client.post(
        url, json={"snapshot": "latest", "confirm": "dock-r", "delete": True}, headers=headers
    )
    assert everything.status_code == 202
    assert everything.json()["job"]["params"]["paths"] == ["/srv/shop"]
    assert everything.json()["job"]["params"]["delete"] is True
    await finish_jobs(db_session_factory)

    async def _protected(db: Any, machine: Any) -> str:
        return "shop"

    monkeypatch.setattr(docker_jobs, "protected_project", _protected)
    protected = await client.post(
        url, json={"snapshot": "latest", "confirm": "dock-r"}, headers=headers
    )
    assert protected.status_code == 409


async def test_backup_snapshots(client, db_session_factory, celery_calls):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)
    backup_id = (await create_backup(client, machine_id, headers)).json()["id"]
    url = f"{base(machine_id)}/backups/{backup_id}/snapshots"

    celery_calls.result_for[SNAPSHOTS] = {"ok": True, "snapshots": [{"id": "0123abcd"}]}
    response = await client.get(url, headers=headers)
    assert response.status_code == 200, response.text
    assert response.json() == [{"id": "0123abcd"}]

    celery_calls.result_for[SNAPSHOTS] = {"ok": False, "error": "wrong password"}
    failed = await client.get(url, headers=headers)
    assert failed.status_code == 502


async def test_backup_export_restore_to_and_every_snapshot(client, db_session_factory):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)
    created = await create_backup(client, machine_id, headers, all_snapshots=True)
    assert created.json()["all_snapshots"] is True
    backup_id = created.json()["id"]

    exported = await client.get(f"{base(machine_id)}/backups/export", headers=headers)
    assert exported.status_code == 200
    assert_no_secrets(exported.text)
    [definition] = exported.json()["backups"]
    assert definition["repository"] is None
    assert definition["env_names"] == ["AWS_SECRET_ACCESS_KEY"]
    one = await client.get(f"{base(machine_id)}/backups/{backup_id}/export", headers=headers)
    assert one.json()["backups"] == [definition]

    url = f"{base(machine_id)}/backups/{backup_id}/restore-to"
    body = {"snapshot": "0123abcd", "source": "/backup/volumes/old", "volume": "fresh"}
    refused = await client.post(url, json=body, headers=headers)
    assert refused.status_code == 400
    queued = await client.post(url, json={**body, "confirm": "dock"}, headers=headers)
    assert queued.status_code == 202, queued.text
    assert queued.json()["job"]["kind"] == "backup_restore"
    await finish_jobs(db_session_factory)
    both = await client.post(
        url, json={**body, "path": "/srv/x", "confirm": "dock"}, headers=headers
    )
    assert both.status_code == 400


async def test_backup_delete_and_other_machines(client, db_session_factory):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)
    other_id = await docker_machine(client, db_session_factory, headers, name="dock-other")
    foreign = (await create_backup(client, other_id, headers)).json()["id"]
    url = f"{base(machine_id)}/backups/{foreign}"

    assert (await client.get(url, headers=headers)).status_code == 404
    assert (await client.put(url, json={"name": "x"}, headers=headers)).status_code == 404
    deleted = await client.delete(url, headers=headers)
    assert deleted.status_code == 404
    assert (await client.get(f"{url}/snapshots", headers=headers)).status_code == 404
    assert (await client.post(f"{url}/run", headers=headers)).status_code == 404
    restore = await client.post(
        f"{url}/restore", json={"snapshot": "latest", "confirm": "dock"}, headers=headers
    )
    assert restore.status_code == 404
    assert (await client.get(f"{base(machine_id)}/backups", headers=headers)).json() == []

    own = (await create_backup(client, machine_id, headers)).json()["id"]
    deleted = await client.delete(f"{base(machine_id)}/backups/{own}", headers=headers)
    assert deleted.status_code == 200
    assert deleted.json() == {"ok": True}
    assert (await client.get(f"{base(machine_id)}/backups", headers=headers)).json() == []
    assert ("machine.docker.backup.delete", "success") in await audit_actions(db_session_factory)
    # The other machine's backup is untouched.
    assert len((await client.get(f"{base(other_id)}/backups", headers=headers)).json()) == 1


# --- Files ----------------------------------------------------------------------------


async def test_files_list_read_write_mkdir_delete(client, db_session_factory, celery_calls):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)
    files = f"{base(machine_id)}/containers/web/files"

    celery_calls.result_for[FILES] = {"ok": True, "entries": [{"name": "etc", "type": "dir"}]}
    listed = await client.get(f"{files}?path=/var/../etc/", headers=headers)
    assert listed.status_code == 200, listed.text
    assert listed.json() == {"path": "/etc", "entries": [{"name": "etc", "type": "dir"}]}
    name, args, _kwargs = celery_calls[-1]
    assert name == FILES
    assert args[1:] == ("list", "container", "web", "/etc")

    celery_calls.result_for[FILES] = {
        "ok": True,
        "size": 5,
        "mode": 420,
        "uid": 0,
        "gid": 0,
        "data_b64": base64.b64encode(b"hello").decode(),
    }
    read = await client.get(f"{files}/content?path=/etc/hostname", headers=headers)
    assert read.status_code == 200, read.text
    assert base64.b64decode(read.json()["content_b64"]) == b"hello"
    assert read.json()["mode"] == 420

    celery_calls.result_for[FILES] = {"ok": True}
    written = await client.put(
        f"{files}/content",
        json={"path": "etc/motd", "content_b64": base64.b64encode(b"hi").decode()},
        headers=headers,
    )
    assert written.status_code == 200, written.text
    assert written.json() == {"ok": True, "path": "/etc/motd", "bytes": 2}
    _name, args, kwargs = celery_calls[-1]
    assert args[1:] == ("write", "container", "web", "/etc/motd")
    assert kwargs == {"data_b64": base64.b64encode(b"hi").decode()}

    mkdir = await client.post(f"{files}/mkdir", json={"path": "/etc/new"}, headers=headers)
    assert mkdir.status_code == 200
    assert mkdir.json() == {"ok": True, "path": "/etc/new"}

    deleted = await client.delete(f"{files}?path=/etc/new", headers=headers)
    assert deleted.status_code == 200

    volume = await client.get(f"{base(machine_id)}/volumes/shop_data/files?path=/", headers=headers)
    assert volume.status_code == 200
    assert celery_calls[-1][1][2:4] == ("volume", "shop_data")

    actions = await audit_actions(db_session_factory)
    for action in ("download", "write", "mkdir", "delete"):
        assert (f"machine.docker.file.{action}", "success") in actions


async def test_files_validation(client, db_session_factory, celery_calls):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)
    files = f"{base(machine_id)}/containers/web/files"
    calls_before = len(celery_calls)

    assert (
        await client.get(f"{base(machine_id)}/networks/x/files", headers=headers)
    ).status_code == 404
    assert (
        await client.get(f"{base(machine_id)}/containers/-x/files", headers=headers)
    ).status_code == 404
    deleted = await client.delete(f"{files}?path=/", headers=headers)
    assert deleted.status_code == 400
    deleted = await client.delete(f"{files}?path=/tmp/..", headers=headers)
    assert deleted.status_code == 400
    assert (
        await client.post(f"{files}/mkdir", json={"path": "/"}, headers=headers)
    ).status_code == 400
    root_write = await client.put(
        f"{files}/content", json={"path": "/", "content_b64": ""}, headers=headers
    )
    assert root_write.status_code == 400
    bad_b64 = await client.put(
        f"{files}/content", json={"path": "/a", "content_b64": "!!notbase64"}, headers=headers
    )
    assert bad_b64.status_code == 400
    nul = await client.get(f"{files}?path=/a%00b", headers=headers)
    assert nul.status_code == 400
    missing = await client.get(f"{files}/content", headers=headers)
    assert missing.status_code == 422
    # Nothing reached the worker.
    assert len(celery_calls) == calls_before


async def test_files_worker_errors(client, db_session_factory, celery_calls):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)
    files = f"{base(machine_id)}/containers/web/files"

    celery_calls.result_for[FILES] = {"ok": False, "error": "too_large"}
    too_large = await client.get(f"{files}/content?path=/big", headers=headers)
    assert too_large.status_code == 413
    assert ("machine.docker.file.download", "failure") in await audit_actions(db_session_factory)

    celery_calls.result_for[FILES] = {"ok": False, "error": "No such directory."}
    gone = await client.get(f"{files}?path=/nope", headers=headers)
    assert gone.status_code == 502


async def test_files_need_terminal_and_host_key(client, login_as, db_session_factory):
    headers = await _api_token(client)
    machine_id = await docker_machine(client, db_session_factory, headers)
    unready_id = await docker_machine(client, db_session_factory, headers, "dock-u", ready=False)
    files = f"{base(machine_id)}/containers/web/files"

    unready = await client.get(f"{base(unready_id)}/containers/web/files", headers=headers)
    assert unready.status_code == 400

    limited = await headers_for(
        client,
        login_as,
        {Permission.MACHINE_VIEW, Permission.ACTION_UPDATES, Permission.ACTION_POWER},
    )
    assert (await client.get(files, headers=limited)).status_code == 403
    assert (await client.get(f"{files}/content?path=/a", headers=limited)).status_code == 403
    put = await client.put(
        f"{files}/content", json={"path": "/a", "content_b64": ""}, headers=limited
    )
    assert put.status_code == 403
    assert (
        await client.post(f"{files}/mkdir", json={"path": "/d"}, headers=limited)
    ).status_code == 403
    deleted = await client.delete(f"{files}?path=/a", headers=limited)
    assert deleted.status_code == 403
