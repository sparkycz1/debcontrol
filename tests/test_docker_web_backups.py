"""restic backups on the Docker tab: their settings and restores need
`action.terminal` (they hold the repository's secrets and choose what is
overwritten), running/checking/pruning one needs `action.updates`, a
restore needs the machine's name typed, and the password, environment
and repository credentials are never shown again."""

from __future__ import annotations

import pytest

from app.core.security import decrypt_secret, encrypt_secret
from app.db.models.audit_log import AuditOutcome
from app.db.models.docker import DockerBackup, DockerJobKind
from app.db.models.role import Permission
from tests.test_docker_web_support import (
    BACKUP_ENV_SECRET,
    BACKUP_PASSWORD_SECRET,
    BACKUP_REPO_PASSWORD,
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


# --- Export, import, other hosts' snapshots ---------------------------------


async def test_export_has_the_settings_but_no_secret(client, db_session_factory):
    machine_id = await make_docker_machine(db_session_factory)
    await add_backup(db_session_factory, machine_id)
    await add_backup(db_session_factory, machine_id, name="local")
    async with db_session_factory() as session:
        from sqlalchemy import select

        local = (
            await session.execute(select(DockerBackup).where(DockerBackup.name == "local"))
        ).scalar_one()
        local.repository_encrypted = encrypt_secret("/srv/restic")
        local.repository_display = "/srv/restic"
        await session.commit()

    response = await client.get(f"/machines/{machine_id}/docker/backups/export")

    assert response.status_code == 200
    assert "attachment" in response.headers["content-disposition"]
    for secret in (BACKUP_PASSWORD_SECRET, "backup-env-secret-value", BACKUP_REPO_PASSWORD):
        assert secret not in response.text
    data = response.json()
    assert data["kind"] == "debcontrol.docker-backups" and data["machine"] == MACHINE_NAME
    by_name = {b["name"]: b for b in data["backups"]}
    assert by_name["nightly"]["repository"] is None
    assert by_name["nightly"]["repository_display"] == "rest:https://***@restic.example.test/repo"
    assert by_name["nightly"]["env_names"] == ["AWS_SECRET_ACCESS_KEY"]
    assert by_name["local"]["repository"] == "/srv/restic"
    assert by_name["nightly"]["volumes"] == ["site_data"]
    one = await client.get(
        f"/machines/{machine_id}/docker/backups/{local.id}/export"
    )
    assert [b["name"] for b in one.json()["backups"]] == ["local"]


async def test_import_fills_in_the_new_backup_form_and_saves_nothing(
    client, db_session_factory, celery_calls
):
    machine_id = await make_docker_machine(db_session_factory)
    await add_backup(db_session_factory, machine_id)
    exported = (await client.get(f"/machines/{machine_id}/docker/backups/export")).text
    other_id = await make_docker_machine(db_session_factory, name="newhost")
    csrf = await csrf_token(client, other_id)
    url = f"/machines/{other_id}/docker/backups/import"

    assert (await client.get(url)).status_code == 200
    response = await client.post(
        url,
        data={"csrf_token": csrf},
        files={"file": ("backups.json", exported.encode(), "application/json")},
    )

    assert response.status_code == 200
    assert 'name="name" required maxlength="64" value="nightly"' in response.text
    assert "AWS_SECRET_ACCESS_KEY=" in response.text
    assert 'name="all_snapshots" value="1" checked' in response.text
    assert "rest:https://***@restic.example.test/repo" in response.text
    async with db_session_factory() as session:
        from app.services import docker_backups

        assert await docker_backups.list_backups(session, other_id) == []


async def test_import_of_several_lists_them_and_bad_files_are_refused(
    client, db_session_factory
):
    machine_id = await make_docker_machine(db_session_factory)
    await add_backup(db_session_factory, machine_id)
    await add_backup(db_session_factory, machine_id, name="weekly")
    exported = (await client.get(f"/machines/{machine_id}/docker/backups/export")).text
    csrf = await csrf_token(client, machine_id)
    url = f"/machines/{machine_id}/docker/backups/import"

    listed = await client.post(
        url, data={"csrf_token": csrf}, files={"file": ("b.json", exported.encode())}
    )
    assert listed.status_code == 200
    assert listed.text.count('name="definition"') == 2
    picked = await client.post(
        url, data={"csrf_token": csrf, "definition": '{"name": "weekly", "volumes": ["v1"]}'}
    )
    assert 'value="weekly"' in picked.text

    for content in (b"not json", b'{"kind": "other"}', b'{"kind": "debcontrol.docker-backups",'
                    b' "version": 99, "backups": []}', b"x" * 300_000):
        refused = await client.post(
            url, data={"csrf_token": csrf}, files={"file": ("b.json", content)}
        )
        assert refused.status_code == 400
        assert 'class="alert alert-error"' in refused.text
    no_csrf = await client.post(url, files={"file": ("b.json", exported.encode())})
    assert no_csrf.status_code == 403


async def test_every_snapshot_can_be_listed_and_saved(client, db_session_factory):
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)

    await client.post(
        f"/machines/{machine_id}/docker/backups",
        data=_backup_form(csrf, all_snapshots="1"),
    )

    async with db_session_factory() as session:
        from sqlalchemy import select

        backup = (await session.execute(select(DockerBackup))).scalar_one()
    assert backup.all_snapshots is True


async def test_snapshots_of_other_hosts_offer_restore_into_a_volume(
    client, db_session_factory, celery_calls
):
    machine_id = await make_docker_machine(db_session_factory)
    backup_id = await add_backup(db_session_factory, machine_id)
    async with db_session_factory() as session:
        row = await session.get(DockerBackup, backup_id)
        assert row is not None
        row.all_snapshots = True
        await session.commit()
    foreign = "fedcba98" * 8
    celery_calls.result_for[SNAPSHOTS_TASK] = {
        "ok": True,
        "snapshots": [
            {"id": SNAPSHOT_ID, "short_id": SNAPSHOT_ID[:8], "time": "2026-10-17T03:00:00Z",
             "host": MACHINE_NAME, "tags": ["debcontrol", f"dc-{backup_id}"],
             "paths": ["/backup"], "size_bytes": 1},
            {"id": foreign, "short_id": foreign[:8], "time": "2026-10-01T03:00:00Z",
             "host": "oldbox", "tags": [], "paths": ["/home/kuba"], "size_bytes": 2},
        ],
    }

    panel = await client.get(f"/machines/{machine_id}/docker/backups/{backup_id}/snapshots")

    assert "oldbox" in panel.text
    # In place only for debcontrol's layout; into a volume or directory for all.
    assert panel.text.count('/restore"') == 1
    assert panel.text.count('/restore-to"') == 2


async def test_restore_to_queues_a_job_for_one_target(client, db_session_factory, celery_calls):
    machine_id = await make_docker_machine(db_session_factory)
    backup_id = await add_backup(db_session_factory, machine_id)
    csrf = await csrf_token(client, machine_id)
    url = f"/machines/{machine_id}/docker/backups/{backup_id}/restore-to"
    form = {
        "csrf_token": csrf,
        "snapshot": SNAPSHOT_ID,
        "source": "/backup/volumes/old_data/",
        "target_kind": "volume",
        "target": "new_data",
    }

    refused = await client.post(url, data=form)
    assert refused.status_code == 303
    assert await jobs_of(db_session_factory, machine_id) == []
    [denied] = await audit_entries(db_session_factory, "machine.docker.backup.restore")
    assert denied.outcome == AuditOutcome.DENIED

    queued = await client.post(url, data={**form, "confirm_name": MACHINE_NAME})
    [job] = await jobs_of(db_session_factory, machine_id)
    assert queued.headers["location"] == f"/machines/{machine_id}/docker/jobs/{job.id}"
    assert job.kind == DockerJobKind.BACKUP_RESTORE
    assert job.params == {
        "mode": "to",
        "snapshot": SNAPSHOT_ID,
        "source": "/backup/volumes/old_data",
        "volume": "new_data",
        "path": "",
        "delete": False,
    }
    for bad in ({"source": "../x"}, {"target_kind": "path", "target": "/proc/x"},
                {"target": "bad volume"}, {"snapshot": "nope"}):
        response = await client.post(url, data={**form, "confirm_name": MACHINE_NAME, **bad})
        assert response.status_code == 303
    assert len(await jobs_of(db_session_factory, machine_id)) == 1
