"""restic backups on the Docker tab: their settings and restores need
`action.terminal` (they hold the repository's secrets and choose what is
overwritten), running/checking/pruning one needs `action.updates`, a
restore needs the machine's name typed, and the password, environment
and repository credentials are never shown again."""

from __future__ import annotations

import pytest

from app.core.security import decrypt_secret
from app.db.models.audit_log import AuditOutcome
from app.db.models.docker import DockerBackup, DockerJobKind
from app.db.models.role import Permission
from tests.test_docker_web_support import (
    BACKUP_ENV_SECRET,
    BACKUP_PASSWORD_SECRET,
    MACHINE_NAME,
    RUN_JOB_TASK,
    SNAPSHOT_ID,
    SNAPSHOTS_TASK,
    VIEWER,
    add_backup,
    audit_entries,
    csrf_token,
    follow,
    get_row,
    jobs_of,
    make_docker_machine,
)

UPDATES_AND_POWER = frozenset(
    {Permission.MACHINE_VIEW, Permission.ACTION_UPDATES, Permission.ACTION_POWER}
)
POWER_AND_TERMINAL = frozenset(
    {Permission.MACHINE_VIEW, Permission.ACTION_POWER, Permission.ACTION_TERMINAL}
)


def _backup_form(csrf: str, **overrides: str) -> dict[str, str]:
    return {
        "csrf_token": csrf,
        "name": "offsite",
        "repository": "rest:https://alice:repoPass99@restic.example.test/offsite",
        "password": "createdPassword!",
        "env": "AWS_ACCESS_KEY_ID=createdKeyId",
        "volumes": "site_data\nsite_data\n",
        "paths": "/srv/site/config",
        "excludes": "*.tmp",
        "keep_daily": "7",
        "enabled": "1",
        **overrides,
    }


async def test_create_stores_secrets_encrypted_and_shows_only_a_redacted_repository(
    client, db_session_factory, celery_calls
):
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(f"/machines/{machine_id}/docker/backups", data=_backup_form(csrf))

    assert response.status_code == 303
    backup_id = response.headers["location"].rsplit("/", 1)[-1]
    async with db_session_factory() as session:
        from sqlalchemy import select

        backup = (await session.execute(select(DockerBackup))).scalar_one()
    assert str(backup.id) == backup_id
    assert decrypt_secret(backup.password_encrypted) == "createdPassword!"
    assert backup.env_encrypted is not None
    assert decrypt_secret(backup.env_encrypted) == "AWS_ACCESS_KEY_ID=createdKeyId"
    assert "repoPass99" not in backup.repository_display
    assert backup.volumes == ["site_data"]
    assert backup.keep_daily == 7
    assert celery_calls == []

    page = await follow(client, response.headers["location"])
    for secret in ("createdPassword!", "createdKeyId", "repoPass99"):
        assert secret not in page
    [entry] = await audit_entries(db_session_factory, "machine.docker.backup.create")
    assert "repoPass99" not in str(entry.details)


@pytest.mark.parametrize(
    "overrides",
    [
        {"name": ""},
        {"repository": "ftp://nowhere"},
        {"repository": "/"},
        {"password": ""},
        {"volumes": "", "paths": ""},
        {"volumes": "bad volume"},
        {"paths": "/proc"},
        {"keep_daily": "-1"},
    ],
    ids=["name", "repo-scheme", "repo-root", "password", "nothing", "volume", "path", "keep"],
)
async def test_create_rejects_invalid_input_without_echoing_the_password(
    client, db_session_factory, overrides
):
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/backups", data=_backup_form(csrf, **overrides)
    )

    assert response.status_code == 400
    assert 'class="alert alert-error"' in response.text
    assert "createdPassword!" not in response.text
    assert "createdKeyId" not in response.text


async def test_create_rejects_a_name_already_taken(client, db_session_factory):
    machine_id = await make_docker_machine(db_session_factory)
    await add_backup(db_session_factory, machine_id, name="offsite")
    csrf = await csrf_token(client, machine_id)

    response = await client.post(f"/machines/{machine_id}/docker/backups", data=_backup_form(csrf))

    assert response.status_code == 400


async def test_editing_with_empty_secrets_keeps_the_stored_ones(client, db_session_factory):
    machine_id = await make_docker_machine(db_session_factory)
    backup_id = await add_backup(db_session_factory, machine_id)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/backups/{backup_id}",
        data=_backup_form(csrf, name="nightly", repository="", password="", env="", keep_daily=""),
    )

    backup = await get_row(db_session_factory, DockerBackup, backup_id)
    assert backup is not None
    assert response.status_code == 303
    assert decrypt_secret(backup.password_encrypted) == BACKUP_PASSWORD_SECRET
    assert backup.env_encrypted is not None
    assert decrypt_secret(backup.env_encrypted) == BACKUP_ENV_SECRET
    assert backup.repository_display == "rest:https://***@restic.example.test/repo"
    assert backup.keep_daily is None
    assert len(await audit_entries(db_session_factory, "machine.docker.backup.edit")) == 1


async def test_deleting_forgets_the_backup(client, db_session_factory, celery_calls):
    machine_id = await make_docker_machine(db_session_factory)
    backup_id = await add_backup(db_session_factory, machine_id)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/backups/{backup_id}/delete", data={"csrf_token": csrf}
    )

    assert response.status_code == 303
    assert response.headers["location"] == f"/machines/{machine_id}/docker/backups"
    assert await get_row(db_session_factory, DockerBackup, backup_id) is None
    assert celery_calls == []
    assert len(await audit_entries(db_session_factory, "machine.docker.backup.delete")) == 1


@pytest.mark.parametrize("permissions", [VIEWER, UPDATES_AND_POWER])
async def test_settings_delete_and_restore_need_action_terminal(
    client, login_as, db_session_factory, celery_calls, permissions
):
    machine_id = await make_docker_machine(db_session_factory)
    backup_id = await add_backup(db_session_factory, machine_id)
    await login_as(client, permissions=permissions)
    csrf = await csrf_token(client, machine_id)
    base = f"/machines/{machine_id}/docker/backups"

    for url, data in (
        (base, _backup_form(csrf)),
        (f"{base}/{backup_id}", _backup_form(csrf, name="renamed")),
        (f"{base}/{backup_id}/delete", {"csrf_token": csrf}),
        (
            f"{base}/{backup_id}/restore",
            {
                "csrf_token": csrf,
                "snapshot": SNAPSHOT_ID,
                "volume": "site_data",
                "confirm_name": MACHINE_NAME,
            },
        ),
    ):
        assert (await client.post(url, data=data)).status_code == 403, url

    backup = await get_row(db_session_factory, DockerBackup, backup_id)
    assert backup is not None and backup.name == "nightly"
    assert celery_calls == []


@pytest.mark.parametrize("permissions", [VIEWER, POWER_AND_TERMINAL])
@pytest.mark.parametrize("what", ["run", "check", "forget"])
async def test_backup_jobs_need_action_updates(
    client, login_as, db_session_factory, celery_calls, permissions, what
):
    machine_id = await make_docker_machine(db_session_factory)
    backup_id = await add_backup(db_session_factory, machine_id)
    await login_as(client, permissions=permissions)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/backups/{backup_id}/{what}", data={"csrf_token": csrf}
    )

    assert response.status_code == 403
    assert celery_calls == []


async def test_backup_changes_need_a_csrf_token(client, db_session_factory, celery_calls):
    machine_id = await make_docker_machine(db_session_factory)
    backup_id = await add_backup(db_session_factory, machine_id)
    base = f"/machines/{machine_id}/docker/backups"

    for url in (
        base,
        f"{base}/{backup_id}",
        f"{base}/{backup_id}/delete",
        f"{base}/{backup_id}/restore",
        f"{base}/{backup_id}/run",
    ):
        assert (await client.post(url, data={"confirm_name": MACHINE_NAME})).status_code == 403, url

    assert await get_row(db_session_factory, DockerBackup, backup_id) is not None
    assert celery_calls == []


@pytest.mark.parametrize(
    ("what", "kind", "params"),
    [
        ("run", DockerJobKind.BACKUP_RUN, {}),
        ("check", DockerJobKind.BACKUP_CHECK, {"read_data_percent": 10}),
        ("forget", DockerJobKind.BACKUP_FORGET, {}),
    ],
)
async def test_backup_jobs_are_queued_and_audited(
    client, db_session_factory, celery_calls, what, kind, params
):
    machine_id = await make_docker_machine(db_session_factory)
    backup_id = await add_backup(db_session_factory, machine_id)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/backups/{backup_id}/{what}",
        data={"csrf_token": csrf, "read_data_percent": "10"},
    )

    [job] = await jobs_of(db_session_factory, machine_id)
    assert response.status_code == 303
    assert response.headers["location"] == f"/machines/{machine_id}/docker/jobs/{job.id}"
    assert (job.kind, job.target, job.ref_id) == (kind, "nightly", backup_id)
    assert job.params == params
    assert celery_calls.names == [RUN_JOB_TASK]
    [entry] = await audit_entries(db_session_factory, f"machine.docker.backup.{what}")
    assert entry.details == {"backup": "nightly"}


async def test_forget_without_retention_is_refused(client, db_session_factory, celery_calls):
    machine_id = await make_docker_machine(db_session_factory)
    backup_id = await add_backup(db_session_factory, machine_id, keep_daily=None)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/backups/{backup_id}/forget", data={"csrf_token": csrf}
    )

    assert response.status_code == 303
    assert "error=" in response.headers["location"]
    assert celery_calls == []


async def test_unknown_backup_job_is_not_found(client, db_session_factory, celery_calls):
    machine_id = await make_docker_machine(db_session_factory)
    backup_id = await add_backup(db_session_factory, machine_id)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/backups/{backup_id}/unlock", data={"csrf_token": csrf}
    )

    assert response.status_code == 404
    assert celery_calls == []


@pytest.mark.parametrize("confirm", ["", "wrong", MACHINE_NAME.upper()])
async def test_restore_needs_the_machine_name_typed(
    client, db_session_factory, celery_calls, confirm
):
    machine_id = await make_docker_machine(db_session_factory)
    backup_id = await add_backup(db_session_factory, machine_id)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/backups/{backup_id}/restore",
        data={
            "csrf_token": csrf,
            "snapshot": SNAPSHOT_ID,
            "volume": "site_data",
            "confirm_name": confirm,
        },
    )

    assert response.status_code == 303
    assert response.headers["location"].startswith(
        f"/machines/{machine_id}/docker/backups/{backup_id}?error="
    )
    assert celery_calls == []
    assert await jobs_of(db_session_factory, machine_id) == []
    [entry] = await audit_entries(db_session_factory, "machine.docker.backup.restore")
    assert entry.outcome != AuditOutcome.SUCCESS
    assert "not confirmed" in entry.summary


async def test_restore_with_the_name_typed_queues_only_the_backups_own_sources(
    client, db_session_factory, celery_calls
):
    machine_id = await make_docker_machine(db_session_factory)
    backup_id = await add_backup(db_session_factory, machine_id)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/backups/{backup_id}/restore",
        data={
            "csrf_token": csrf,
            "snapshot": SNAPSHOT_ID,
            "volume": ["site_data", "someone_elses_volume"],
            "path": ["/etc"],
            "delete": "1",
            "confirm_name": MACHINE_NAME,
        },
    )

    [job] = await jobs_of(db_session_factory, machine_id)
    assert response.status_code == 303
    assert response.headers["location"] == f"/machines/{machine_id}/docker/jobs/{job.id}"
    assert job.kind == DockerJobKind.BACKUP_RESTORE
    assert job.params == {
        "snapshot": SNAPSHOT_ID,
        "volumes": ["site_data"],
        "paths": [],
        "delete": True,
    }
    assert celery_calls.names == [RUN_JOB_TASK]
    [entry] = await audit_entries(db_session_factory, "machine.docker.backup.restore")
    assert entry.outcome == AuditOutcome.SUCCESS


@pytest.mark.parametrize(
    "data",
    [
        {"snapshot": "not-a-snapshot", "volume": "site_data"},
        {"snapshot": SNAPSHOT_ID},
    ],
    ids=["bad-snapshot", "nothing-selected"],
)
async def test_restore_rejects_bad_input(client, db_session_factory, celery_calls, data):
    machine_id = await make_docker_machine(db_session_factory)
    backup_id = await add_backup(db_session_factory, machine_id)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/backups/{backup_id}/restore",
        data={"csrf_token": csrf, "confirm_name": MACHINE_NAME, **data},
    )

    assert response.status_code == 303
    assert "error=" in response.headers["location"]
    assert celery_calls == []


async def test_restore_refuses_debcontrols_own_volumes(
    client, db_session_factory, celery_calls, monkeypatch
):
    async def _own_project(db, machine):
        return "site"

    monkeypatch.setattr("app.services.docker_jobs.protected_project", _own_project)
    machine_id = await make_docker_machine(db_session_factory)
    backup_id = await add_backup(db_session_factory, machine_id)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/backups/{backup_id}/restore",
        data={
            "csrf_token": csrf,
            "snapshot": SNAPSHOT_ID,
            "volume": "site_data",
            "confirm_name": MACHINE_NAME,
        },
    )

    assert response.status_code == 303
    assert "error=" in response.headers["location"]
    assert celery_calls == []
    [entry] = await audit_entries(db_session_factory, "machine.docker.backup.restore")
    assert entry.outcome != AuditOutcome.SUCCESS


async def test_snapshots_panel_asks_the_worker_and_shows_its_error(
    client, db_session_factory, celery_calls
):
    machine_id = await make_docker_machine(db_session_factory)
    backup_id = await add_backup(db_session_factory, machine_id)
    celery_calls.result_for[SNAPSHOTS_TASK] = {
        "ok": False,
        "error": "wrong password or no key found",
    }

    response = await client.get(f"/machines/{machine_id}/docker/backups/{backup_id}/snapshots")

    assert response.status_code == 200
    assert "wrong password or no key found" in response.text
    assert celery_calls.names == [SNAPSHOTS_TASK]
    assert celery_calls[0][1] == (str(backup_id),)
