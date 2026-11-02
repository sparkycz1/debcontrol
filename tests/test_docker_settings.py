"""Docker → Settings (`app.services.docker_daemon`, `app.ssh.docker_daemon`):
the fleet's daemon.json keys, writing them and restarting Docker as jobs,
the defaults for new containers, the pages and the REST API — plus the
container actions added with it (pause / resume, autoheal and remove in
bulk, "Update all with a newer image" across the fleet)."""

from __future__ import annotations

import json
import uuid
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy import select

from app.core.app_settings import get_or_create_app_settings
from app.db.models.docker import DockerContainerSetting, DockerJob, DockerJobKind, DockerJobStatus
from app.db.models.machine import Machine
from app.db.models.machine_group import MachineGroup
from app.db.models.role import Permission
from app.services import docker_daemon, self_host
from app.ssh import docker_daemon as daemon_ssh
from app.ssh.docker_cli import CommandOutput
from app.tasks import docker_jobs as tasks
from tests.conftest import RecordedCeleryCalls
from tests.test_docker_autoheal_checks_host import _set_host_check
from tests.test_docker_tasks_jobs import _add, _get, _job, _machine, install_fake_machine
from tests.test_docker_web_support import (
    RUN_JOB_TASK,
    audit_entries,
    csrf_token,
    jobs_of,
    make_docker_machine,
)
from tests.test_update_history import _api_token

CONTAINER_ACTION_TASK = "app.tasks.jobs.run_container_action"

FULL_FORM = {
    "log_driver": "local",
    "log_max_size": "20M",
    "log_max_file": "5",
    "live_restore": "on",
    "no_new_privileges": "off",
    "address_pools": "10.210.0.0/16 24\n172.30.0.0/16:26\n",
    "registry_mirrors": "https://mirror.example.com/",
    "dns": "192.168.1.1 1.1.1.1",
    "builder_keep_storage": "20gb",
}


@pytest.fixture
def own_host(monkeypatch: pytest.MonkeyPatch) -> set[uuid.UUID]:
    hosts: set[uuid.UUID] = set()

    async def fake_find(_db: Any) -> self_host.SelfHost:
        return self_host.SelfHost(hosts=frozenset(hosts))

    monkeypatch.setattr(self_host, "find", fake_find)
    return hosts


async def _configure(db_session_factory: Any, config: dict[str, Any], **extra: Any) -> None:
    async with db_session_factory() as db:
        settings = await get_or_create_app_settings(db)
        settings.docker_daemon_config = config
        for name, value in extra.items():
            setattr(settings, name, value)
        await db.commit()


# --- Validating and merging -------------------------------------------------------------


def test_clean_validates_and_normalises_every_field() -> None:
    assert docker_daemon.clean(FULL_FORM) == {
        "log_driver": "local",
        "log_max_size": "20m",
        "log_max_file": 5,
        "live_restore": True,
        "no_new_privileges": False,
        "address_pools": [
            {"base": "10.210.0.0/16", "size": 24},
            {"base": "172.30.0.0/16", "size": 26},
        ],
        "registry_mirrors": ["https://mirror.example.com"],
        "dns": ["192.168.1.1", "1.1.1.1"],
        "builder_keep_storage": "20GB",
    }
    # Everything left empty: nothing is managed.
    assert docker_daemon.clean(dict.fromkeys(docker_daemon.FIELDS, "")) == {}


@pytest.mark.parametrize(
    ("raw", "field", "key"),
    [
        ({"log_driver": "syslog"}, "log_driver", "choice"),
        ({"log_max_size": "20"}, "log_max_size", "size"),
        ({"log_max_size": "1m; rm -rf /"}, "log_max_size", "size"),
        ({"log_max_file": "0"}, "log_max_file", "files"),
        ({"log_driver": "journald", "log_max_size": "10m"}, "log_max_size", "rotation_driver"),
        ({"live_restore": "maybe"}, "live_restore", "choice"),
        ({"address_pools": "8.8.0.0/16 24"}, "address_pools", "pool"),
        ({"address_pools": "10.0.0.0/24 16"}, "address_pools", "pool"),
        ({"address_pools": "10.0.0.0/16 30"}, "address_pools", "pool"),
        ({"address_pools": "fd00::/48 64"}, "address_pools", "pool"),
        ({"address_pools": "10.0.0.1/16 24"}, "address_pools", "pool"),
        (
            {"address_pools": "\n".join(f"10.{i}.0.0/16 24" for i in range(11))},
            "address_pools",
            "too_many",
        ),
        ({"registry_mirrors": "ftp://mirror"}, "registry_mirrors", "mirror"),
        ({"registry_mirrors": "https://user:pw@mirror"}, "registry_mirrors", "mirror"),
        ({"dns": "dns.google"}, "dns", "dns"),
        ({"dns": "1.1.1.1 1.0.0.1 8.8.8.8 8.8.4.4 9.9.9.9"}, "dns", "too_many"),
        ({"builder_keep_storage": "20G"}, "builder_keep_storage", "keep"),
    ],
)
def test_clean_refuses_bad_values(raw: dict[str, Any], field: str, key: str) -> None:
    with pytest.raises(docker_daemon.DaemonSettingsError) as caught:
        docker_daemon.clean(raw)
    assert caught.value.field == field
    assert caught.value.key == f"docker.settings.error.{key}"


def test_form_values_round_trip() -> None:
    config = docker_daemon.clean(FULL_FORM)
    assert docker_daemon.clean(docker_daemon.form_values(config)) == config
    assert docker_daemon.form_values(None) == dict.fromkeys(docker_daemon.FIELDS, "")


def test_merge_keeps_every_other_key_and_managed_view_reads_it_back() -> None:
    config = docker_daemon.clean(FULL_FORM)
    daemon = {
        "data-root": "/srv/docker",
        "log-opts": {"labels": "app"},
        "builder": {"gc": {"policy": [{"keepStorage": "1GB"}]}},
        "insecure-registries": ["registry.lan:5000"],
    }

    merged = docker_daemon.merge(daemon, config)

    assert merged["data-root"] == "/srv/docker"
    assert merged["insecure-registries"] == ["registry.lan:5000"]
    assert merged["log-opts"] == {"labels": "app", "max-size": "20m", "max-file": "5"}
    assert merged["builder"]["gc"]["policy"] == [{"keepStorage": "1GB"}]
    assert merged["builder"]["gc"]["defaultKeepStorage"] == "20GB"
    assert merged["live-restore"] is True and merged["no-new-privileges"] is False
    assert daemon == {
        "data-root": "/srv/docker",
        "log-opts": {"labels": "app"},
        "builder": {"gc": {"policy": [{"keepStorage": "1GB"}]}},
        "insecure-registries": ["registry.lan:5000"],
    }, "the machine's file is not changed in place"
    assert docker_daemon.managed_view(merged) == config
    assert docker_daemon.differences(config, docker_daemon.managed_view(merged)) == []


def test_differences_list_only_managed_keys() -> None:
    config = {"log_driver": "local", "live_restore": True}
    current = {"log_driver": "json-file", "dns": ["9.9.9.9"]}

    diffs = docker_daemon.differences(config, current)

    assert [(d.field, d.current, d.wanted) for d in diffs] == [
        ("log_driver", "json-file", "local"),
        ("live_restore", None, True),
    ]


def test_scope_and_machine_status() -> None:
    group = uuid.uuid4()
    inside = _machine(group_id=group)
    outside = _machine(group_id=None)
    inside.docker_host_check = {"facts": {"daemon_config": {"log_driver": "json-file"}}}
    inside.docker_daemon_state = {"restart_pending": True, "applied_at": "x"}

    settings: Any = SimpleNamespace(
        docker_daemon_config={"log_driver": "local"},
        docker_daemon_group_ids=[str(group), "not-a-uuid"],
    )
    status = docker_daemon.machine_status(inside, settings)

    assert status["in_scope"] and status["checked"] and status["restart_pending"]
    assert status["differences"] == [
        {"field": "log_driver", "current": "json-file", "wanted": "local"}
    ]
    assert docker_daemon.machine_status(outside, settings)["in_scope"] is False
    settings.docker_daemon_config = None
    assert docker_daemon.machine_status(inside, settings)["in_scope"] is False


# --- The scripts ---------------------------------------------------------------------


def test_parse_read_never_guesses_at_a_broken_file() -> None:
    present = daemon_ssh.parse_read('@@BEGIN\n{"log-driver": "local"}\n@@END present\n')
    missing = daemon_ssh.parse_read("@@BEGIN\n\n@@END missing\n")
    invalid = daemon_ssh.parse_read("@@BEGIN\n{nope\n@@END present\n")
    a_list = daemon_ssh.parse_read("@@BEGIN\n[1]\n@@END present\n")
    nothing = daemon_ssh.parse_read("permission denied")

    assert (present.present, present.content, present.error) == (
        True,
        {"log-driver": "local"},
        None,
    )
    assert (missing.present, missing.content, missing.error) == (False, {}, None)
    assert invalid.error == "invalid" and a_list.error == "invalid"
    assert nothing.error == "unreadable"


def test_scripts_take_the_file_on_stdin_and_restore_on_failure() -> None:
    assert 'cat > "$tmp"' in daemon_ssh.WRITE_SCRIPT
    assert "dockerd --validate" in daemon_ssh.WRITE_SCRIPT
    assert daemon_ssh.BACKUP in daemon_ssh.WRITE_SCRIPT
    assert "sudo -n true" in daemon_ssh.RESTART_SCRIPT
    assert f"cp -p {daemon_ssh.BACKUP} {daemon_ssh.DAEMON_JSON}" in daemon_ssh.RESTART_SCRIPT
    assert daemon_ssh.validated("@@VALID yes\n@@WRITTEN\n") == "yes"
    assert daemon_ssh.validated("@@WRITTEN\n") == "unsupported"
    assert daemon_ssh.restart_outcome("@@UP\n") == "up"
    assert daemon_ssh.restart_outcome("@@DOWN\n@@RESTORED\n@@UP_AFTER_RESTORE\n") == "restored"
    assert daemon_ssh.restart_outcome("@@NO_ROOT\n") == "no_root"
    assert daemon_ssh.restart_outcome("@@DOWN\n") == "down"


# --- The jobs ------------------------------------------------------------------------------


def _fake_scripts(
    monkeypatch: pytest.MonkeyPatch, answers: dict[str, CommandOutput]
) -> list[tuple[str, str | None]]:
    sent: list[tuple[str, str | None]] = []

    async def fake_run_script(
        _machine: Any, _secret: Any, _timeout: int, script: str, **kwargs: Any
    ) -> CommandOutput:
        sent.append((script, kwargs.get("stdin")))
        for needle, output in answers.items():
            if needle in script:
                return output
        return CommandOutput(0, "")

    monkeypatch.setattr(tasks, "run_script", fake_run_script)
    return sent


async def _daemon_job(db_session_factory: Any, kind: str, **machine: Any) -> tuple[Machine, Any]:
    row = _machine(**machine)
    job = _job(row, kind, "daemon.json" if kind == DockerJobKind.DAEMON_CONFIG else "docker")
    await _add(db_session_factory, row, job)
    return row, job


async def test_writing_daemon_json_merges_validates_and_waits_for_a_restart(
    db_session_factory: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    install_fake_machine(monkeypatch, db_session_factory)
    await _configure(db_session_factory, {"log_driver": "local", "live_restore": True})
    machine, job = await _daemon_job(
        db_session_factory,
        DockerJobKind.DAEMON_CONFIG,
        docker_host_check={"ok": True, "facts": {"daemon_config": {}}},
    )
    sent = _fake_scripts(
        monkeypatch,
        {
            "echo @@BEGIN": CommandOutput(
                0, '@@BEGIN\n{"data-root": "/srv/docker"}\n@@END present\n'
            ),
            "dockerd --validate": CommandOutput(0, "@@VALID yes\n@@WRITTEN\n"),
        },
    )

    await tasks._run_docker_job(str(job.id))

    stored = await _get(db_session_factory, DockerJob, job.id)
    assert stored.status == DockerJobStatus.SUCCEEDED
    assert stored.result["fields"] == ["live_restore", "log_driver"]
    [(_read, read_stdin), (write, written)] = sent
    assert read_stdin is None
    assert "data-root" not in write, "the file goes on stdin, never into the command"
    assert json.loads(written or "") == {
        "data-root": "/srv/docker",
        "live-restore": True,
        "log-driver": "local",
    }
    row = await _get(db_session_factory, Machine, machine.id)
    assert row.docker_daemon_state["restart_pending"] is True
    assert row.docker_daemon_state["validated"] == "yes"
    assert row.docker_host_check["facts"]["daemon_config"] == {
        "log_driver": "local",
        "live_restore": True,
    }


async def test_an_unchanged_file_is_not_written(
    db_session_factory: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    install_fake_machine(monkeypatch, db_session_factory)
    await _configure(db_session_factory, {"log_driver": "local"})
    machine, job = await _daemon_job(db_session_factory, DockerJobKind.DAEMON_CONFIG)
    sent = _fake_scripts(
        monkeypatch,
        {"echo @@BEGIN": CommandOutput(0, '@@BEGIN\n{"log-driver": "local"}\n@@END present\n')},
    )

    await tasks._run_docker_job(str(job.id))

    stored = await _get(db_session_factory, DockerJob, job.id)
    assert stored.status == DockerJobStatus.SKIPPED
    assert len(sent) == 1
    row = await _get(db_session_factory, Machine, machine.id)
    assert not row.docker_daemon_state.get("restart_pending")


@pytest.mark.parametrize(
    ("read", "write", "error"),
    [
        ("@@BEGIN\n{broken\n@@END present\n", None, "not valid JSON"),
        (
            "@@BEGIN\n\n@@END missing\n",
            CommandOutput(21, "@@INVALID\nbad key\n"),
            "efused the new settings",
        ),
        ("@@BEGIN\n\n@@END missing\n", CommandOutput(24, "@@VALID yes\n"), "needs root"),
    ],
)
async def test_writing_fails_safely(
    db_session_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
    read: str,
    write: CommandOutput | None,
    error: str,
) -> None:
    install_fake_machine(monkeypatch, db_session_factory)
    await _configure(db_session_factory, {"log_driver": "local"})
    machine, job = await _daemon_job(db_session_factory, DockerJobKind.DAEMON_CONFIG)
    answers = {"echo @@BEGIN": CommandOutput(0, read)}
    if write is not None:
        answers["dockerd --validate"] = write
    sent = _fake_scripts(monkeypatch, answers)

    await tasks._run_docker_job(str(job.id))

    stored = await _get(db_session_factory, DockerJob, job.id)
    assert stored.status == DockerJobStatus.FAILED
    assert error in stored.error
    assert len(sent) == (1 if write is None else 2)
    row = await _get(db_session_factory, Machine, machine.id)
    assert not (row.docker_daemon_state or {}).get("restart_pending")


@pytest.mark.parametrize(
    ("output", "status", "pending", "error"),
    [
        ("@@UP\n", DockerJobStatus.SUCCEEDED, False, None),
        ("@@DOWN\n@@RESTORED\n@@UP_AFTER_RESTORE\n", DockerJobStatus.FAILED, True, "put back"),
        ("@@NO_ROOT\n", DockerJobStatus.FAILED, True, "needs root"),
    ],
)
async def test_restarting_docker(
    db_session_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
    own_host: set[uuid.UUID],
    output: str,
    status: DockerJobStatus,
    pending: bool,
    error: str | None,
) -> None:
    install_fake_machine(monkeypatch, db_session_factory)
    machine, job = await _daemon_job(
        db_session_factory,
        DockerJobKind.DAEMON_RESTART,
        docker_daemon_state={"restart_pending": True},
    )
    _fake_scripts(monkeypatch, {"systemctl restart docker": CommandOutput(0, output)})

    await tasks._run_docker_job(str(job.id))

    stored = await _get(db_session_factory, DockerJob, job.id)
    row = await _get(db_session_factory, Machine, machine.id)
    assert stored.status == status
    assert row.docker_daemon_state["restart_pending"] is pending
    assert (row.docker_daemon_state.get("error") is None) == (error is None)
    if error:
        assert error in row.docker_daemon_state["error"]


async def test_docker_is_never_restarted_where_debcontrol_runs(
    db_session_factory: Any, monkeypatch: pytest.MonkeyPatch, own_host: set[uuid.UUID]
) -> None:
    install_fake_machine(monkeypatch, db_session_factory)
    machine, job = await _daemon_job(db_session_factory, DockerJobKind.DAEMON_RESTART)
    own_host.add(machine.id)
    sent = _fake_scripts(monkeypatch, {})

    await tasks._run_docker_job(str(job.id))

    stored = await _get(db_session_factory, DockerJob, job.id)
    assert stored.status == DockerJobStatus.FAILED
    assert "debcontrol runs on this machine" in stored.error
    assert sent == []


# --- Defaults for new containers ---------------------------------------------------------


async def test_defaults_go_to_new_containers_only(db_session_factory: Any) -> None:
    machine = _machine(
        docker_containers=[
            {"name": "old"},
            {"name": "api", "health": "healthy"},
            {"name": "plain", "health": None},
            {"name": "mine", "health": "healthy"},
            {"name": "debcontrol-app-1", "compose_project": "debcontrol", "health": "healthy"},
        ]
    )
    await _add(
        db_session_factory,
        machine,
        DockerContainerSetting(machine_id=machine.id, name="mine", auto_update=False),
    )
    previous = [{"name": "old"}]

    async with db_session_factory() as db:
        settings = await get_or_create_app_settings(db)
        none = await docker_daemon.apply_container_defaults(
            db, machine, previous, settings, protected_project="debcontrol"
        )
        settings.docker_default_update_policy = "minor"
        settings.docker_default_vulnerability_gate = "critical"
        settings.docker_default_autoheal = True
        first_sample = await docker_daemon.apply_container_defaults(
            db, machine, None, settings, protected_project="debcontrol"
        )
        added = await docker_daemon.apply_container_defaults(
            db, machine, previous, settings, protected_project="debcontrol"
        )
        await db.commit()
        rows = {r.name: r for r in (await db.execute(select(DockerContainerSetting))).scalars()}

    assert none == [] and first_sample == []
    assert added == ["api", "plain"]
    assert (rows["api"].auto_update, rows["api"].update_policy) == (True, "minor")
    assert rows["api"].vulnerability_gate == "critical"
    assert rows["api"].autoheal is True
    assert rows["plain"].autoheal is False, "autoheal only with a health check"
    assert rows["mine"].auto_update is False, "a container's own settings stay"
    assert "debcontrol-app-1" not in rows and "old" not in rows


# --- Pages ---------------------------------------------------------------------------------


async def test_the_settings_page_saves_and_audits(client: Any, db_session_factory: Any) -> None:
    async with db_session_factory() as db:
        group = MachineGroup(name="Docker hosts")
        db.add(group)
        await db.commit()
        group_id = group.id
    page = await client.get("/docker/settings")
    assert page.status_code == 200
    assert 'name="log_driver"' in page.text and "Docker hosts" in page.text
    csrf = client.cookies.get("csrftoken")

    saved = await client.post(
        "/docker/settings",
        data={
            **FULL_FORM,
            "csrf_token": csrf,
            "group": [str(group_id), str(uuid.uuid4()), "junk"],
            "default_update_policy": "patch",
            "default_vulnerability_gate": "high",
            "default_autoheal": "1",
        },
    )
    bad = await client.post(
        "/docker/settings", data={"csrf_token": csrf, "dns": "dns.google", "log_driver": "local"}
    )

    assert saved.status_code == 303
    assert bad.status_code == 400
    assert "DNS servers are IP addresses" in bad.text
    assert 'value="dns.google"' in bad.text, "the form keeps what was typed"
    async with db_session_factory() as db:
        settings = await get_or_create_app_settings(db)
        assert settings.docker_daemon_config == docker_daemon.clean(FULL_FORM)
        assert settings.docker_daemon_group_ids == [str(group_id)]
        assert settings.docker_default_update_policy == "patch"
        assert settings.docker_default_vulnerability_gate == "high"
        assert settings.docker_default_autoheal is True
    [entry] = await audit_entries(db_session_factory, "docker.settings.update")
    assert entry.details is not None
    assert "groups" in entry.details["changed"] and "dns" in entry.details["changed"]


async def test_the_settings_page_needs_its_permissions(
    client: Any, login_as: Any, db_session_factory: Any
) -> None:
    await client.get("/docker/settings")
    no_csrf = await client.post("/docker/settings", data={"log_driver": "local"})
    await login_as(client, permissions={Permission.MACHINE_VIEW})
    hidden = await client.get("/docker/containers")
    denied_page = await client.get("/docker/settings")
    await login_as(
        client, permissions={Permission.MACHINE_VIEW, Permission.SETTINGS_VIEW}, username="viewer"
    )
    read_only = await client.get("/docker/settings")
    csrf = client.cookies.get("csrftoken")
    denied = await client.post("/docker/settings", data={"csrf_token": csrf, "log_driver": "local"})
    apply = await client.post("/docker/settings/apply", data={"csrf_token": csrf})
    restart = await client.post("/docker/settings/restart", data={"csrf_token": csrf})

    assert no_csrf.status_code == 403
    assert 'href="/docker/settings"' not in hidden.text
    assert denied_page.status_code == 403
    assert read_only.status_code == 200 and "disabled" in read_only.text
    assert 'type="submit" class="button">Save' not in read_only.text
    assert (denied.status_code, apply.status_code, restart.status_code) == (403, 403, 403)
    async with db_session_factory() as db:
        assert (await get_or_create_app_settings(db)).docker_daemon_config is None


async def test_a_group_limited_account_cannot_change_fleet_settings(
    client: Any, login_as: Any, db_session_factory: Any
) -> None:
    async with db_session_factory() as db:
        group = MachineGroup(name="Team")
        db.add(group)
        await db.commit()
        group_id = group.id
    await login_as(
        client,
        permissions={Permission.SETTINGS_VIEW, Permission.SETTINGS_MANAGE},
        group_ids={group_id},
    )
    await client.get("/docker/settings")
    csrf = client.cookies.get("csrftoken")

    response = await client.post("/docker/settings", data={"csrf_token": csrf, "dns": "1.1.1.1"})

    assert response.status_code == 403


async def test_apply_and_restart_queue_a_job_per_machine(
    client: Any,
    db_session_factory: Any,
    celery_calls: RecordedCeleryCalls,
    own_host: set[uuid.UUID],
) -> None:
    first = await make_docker_machine(db_session_factory)
    second = await make_docker_machine(db_session_factory, name="second")
    await _configure(db_session_factory, {"live_restore": True})
    await client.get("/docker/settings")
    csrf = client.cookies.get("csrftoken")

    applied = await client.post("/docker/settings/apply", data={"csrf_token": csrf})

    assert applied.status_code == 303
    kinds = [j.kind for j in await jobs_of(db_session_factory, first)]
    assert kinds == [DockerJobKind.DAEMON_CONFIG]
    assert [j.kind for j in await jobs_of(db_session_factory, second)] == kinds
    assert celery_calls.names.count(RUN_JOB_TASK) == 2
    [entry] = await audit_entries(db_session_factory, "docker.settings.apply")
    assert entry.details is not None and entry.details["count"] == 2

    async with db_session_factory() as db:
        for machine_id in (first, second):
            row = await db.get(Machine, machine_id)
            assert row is not None
            row.docker_daemon_state = {"restart_pending": True}
        await db.commit()
    own_host.add(second)
    page = await client.get("/docker/settings")
    assert "Restart Docker where waiting (1)" in page.text, "not on debcontrol's own machine"

    restarted = await client.post("/docker/settings/restart", data={"csrf_token": csrf})

    assert restarted.status_code == 303
    restarts = [
        j
        for j in await jobs_of(db_session_factory, first)
        if j.kind == DockerJobKind.DAEMON_RESTART
    ]
    assert len(restarts) == 1
    assert len(await audit_entries(db_session_factory, "machine.docker.daemon.restart")) == 1, (
        "debcontrol's own machine is left out"
    )


async def test_the_host_page_shows_what_differs_and_writes_here(
    client: Any,
    db_session_factory: Any,
    celery_calls: RecordedCeleryCalls,
    own_host: set[uuid.UUID],
) -> None:
    machine_id = await make_docker_machine(db_session_factory)
    await _set_host_check(db_session_factory, machine_id)
    async with db_session_factory() as db:
        row = await db.get(Machine, machine_id)
        assert row is not None and row.docker_host_check
        row.docker_host_check = {
            **row.docker_host_check,
            "facts": {
                **row.docker_host_check["facts"],
                "daemon_config": {"log_driver": "json-file"},
            },
        }
        await db.commit()
    quiet = await client.get(f"/machines/{machine_id}/docker/host")
    assert "Docker → Settings on this machine" not in quiet.text
    await _configure(db_session_factory, {"log_driver": "local"})
    csrf = await csrf_token(client, machine_id)

    page = await client.get(f"/machines/{machine_id}/docker/host")
    applied = await client.post(
        f"/machines/{machine_id}/docker/daemon/apply", data={"csrf_token": csrf}
    )
    own_host.add(machine_id)
    refused = await client.post(
        f"/machines/{machine_id}/docker/daemon/restart", data={"csrf_token": csrf}
    )

    assert "Docker → Settings on this machine" in page.text
    assert '<code>"json-file"</code>' in page.text and '<code>"local"</code>' in page.text
    assert applied.status_code == 303 and "/docker/jobs/" in applied.headers["location"]
    assert refused.status_code == 303 and "error=" in refused.headers["location"]
    kinds = [j.kind for j in await jobs_of(db_session_factory, machine_id)]
    assert kinds == [DockerJobKind.DAEMON_CONFIG]
    assert len(await audit_entries(db_session_factory, "machine.docker.daemon.apply")) == 1


# --- REST API --------------------------------------------------------------------------


async def test_settings_through_the_api(
    client: Any, db_session_factory: Any, celery_calls: RecordedCeleryCalls
) -> None:
    machine_id = await make_docker_machine(db_session_factory)
    headers = await _api_token(client)

    empty = await client.get("/api/v1/docker/settings", headers=headers)
    nothing = await client.post("/api/v1/docker/settings/apply", headers=headers)
    bad = await client.put(
        "/api/v1/docker/settings", headers=headers, json={"daemon": {"dns": ["dns.google"]}}
    )
    saved = await client.put(
        "/api/v1/docker/settings",
        headers=headers,
        json={
            "daemon": {"log_driver": "local", "log_max_size": "10m", "live_restore": True},
            "defaults": {"update_policy": "patch", "autoheal": True},
        },
    )
    machines = await client.get("/api/v1/docker/settings/machines", headers=headers)
    applied = await client.post("/api/v1/docker/settings/apply", headers=headers)
    again = await client.post(f"/api/v1/machines/{machine_id}/docker/daemon/apply", headers=headers)

    assert empty.json()["daemon"] == {} and empty.json()["defaults"]["autoheal"] is False
    assert nothing.status_code == 409
    assert bad.status_code == 422
    assert bad.json()["detail"] == {"field": "dns", "error": "docker.settings.error.dns"}
    assert saved.status_code == 200
    assert saved.json()["daemon"] == {
        "log_driver": "local",
        "log_max_size": "10m",
        "live_restore": True,
    }
    assert saved.json()["defaults"] == {
        "update_policy": "patch",
        "vulnerability_gate": None,
        "autoheal": True,
    }
    [row] = machines.json()["machines"]
    assert row["id"] == str(machine_id) and row["in_scope"] is True
    assert applied.json()["queued"] == 1
    assert again.status_code == 409, "the same job is already waiting"
    assert len(await audit_entries(db_session_factory, "docker.settings.update")) == 1


# --- Container actions -------------------------------------------------------------------


async def test_fleet_bulk_pauses_resumes_and_removes(
    client: Any, db_session_factory: Any, celery_calls: RecordedCeleryCalls
) -> None:
    machine_id = await make_docker_machine(db_session_factory)
    await client.get("/docker/containers")
    csrf = client.cookies.get("csrftoken")

    for action in ("pause", "unpause", "remove"):
        response = await client.post(
            "/docker/containers/bulk",
            data={"csrf_token": csrf, "action": action, "container": [f"{machine_id}/web"]},
        )
        assert response.status_code == 303

    calls = [kw["action"] for name, _a, kw in celery_calls if name == CONTAINER_ACTION_TASK]
    assert calls[:2] == ["pause", "unpause"]
    assert len(await audit_entries(db_session_factory, "machine.container.pause")) == 1


async def test_bulk_autoheal_on_a_machine(client: Any, db_session_factory: Any) -> None:
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/containers/bulk",
        data={"csrf_token": csrf, "action": "autoheal_on", "container": ["web", "worker", "ghost"]},
    )

    assert response.status_code == 303
    async with db_session_factory() as db:
        rows = (await db.execute(select(DockerContainerSetting))).scalars().all()
    assert sorted((r.name, r.autoheal) for r in rows) == [("web", True), ("worker", True)]
    assert await audit_entries(db_session_factory, "machine.docker.container.autoheal_settings")


async def test_pause_is_refused_for_debcontrols_own_container(
    client: Any, db_session_factory: Any, celery_calls: RecordedCeleryCalls, monkeypatch: Any
) -> None:
    machine_id = await make_docker_machine(db_session_factory)

    async def fake_protected(_db: Any, _machine: Any) -> str:
        return "site"

    monkeypatch.setattr("app.services.docker_jobs.protected_project", fake_protected)
    csrf = await csrf_token(client, machine_id)
    headers = await _api_token(client)

    web = await client.post(
        f"/machines/{machine_id}/containers/web/pause", data={"csrf_token": csrf}
    )
    api = await client.post(f"/api/v1/machines/{machine_id}/containers/web/pause", headers=headers)

    assert web.status_code == 303 and "error=" in web.headers["location"]
    assert api.status_code == 409
    assert CONTAINER_ACTION_TASK not in celery_calls.names


async def test_update_all_across_the_fleet(
    client: Any, db_session_factory: Any, celery_calls: RecordedCeleryCalls, login_as: Any
) -> None:
    first = await make_docker_machine(db_session_factory)
    second = await make_docker_machine(db_session_factory, name="second")
    page = await client.get("/docker/containers")
    assert "Update all with a newer image (2)" in page.text
    csrf = client.cookies.get("csrftoken")
    headers = await _api_token(client)

    web = await client.post("/docker/containers/update-all", data={"csrf_token": csrf})
    api = await client.post("/api/v1/docker/containers/update-all", headers=headers)

    assert web.status_code == 303
    targets = {
        j.target
        for machine_id in (first, second)
        for j in await jobs_of(db_session_factory, machine_id)
        if j.kind == DockerJobKind.CONTAINER_UPDATE
    }
    assert targets == {"web"}
    # Everything was already queued by the button: nothing new, no error.
    assert api.status_code == 200 and api.json()["queued"] == 0

    await login_as(client, permissions={Permission.MACHINE_VIEW, Permission.ACTION_POWER})
    await client.get("/docker/containers")
    denied = await client.post(
        "/docker/containers/update-all", data={"csrf_token": client.cookies.get("csrftoken")}
    )
    assert denied.status_code == 403
