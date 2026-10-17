"""Starting Docker jobs (`app.services.docker_actions`): what is checked
before anything is queued, how debcontrol's own Compose project is
protected (`app.services.docker_jobs`), container settings and job
retention, and the scheduled Docker actions built on top
(`app.scheduling.builtin_actions`)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select

from app.db.models.docker import (
    DockerBackup,
    DockerJob,
    DockerJobKind,
    DockerJobStatus,
    DockerStack,
)
from app.db.models.machine import AuthMethod, Machine
from app.scheduling.actions import get_action
from app.scheduling.builtin_actions import register_builtin_actions
from app.services import docker_actions, docker_jobs, self_host
from app.ssh.docker_cli import DockerCommandError
from app.ssh.docker_prune import PruneOptions
from tests.conftest import RecordedCeleryCalls

RUN_JOB = "app.tasks.docker_jobs.run_docker_job"
IMAGE_ID = "sha256:" + "a" * 64

CONTAINERS = [
    {"name": "web", "image": "nginx:1.27", "compose_project": "shop"},
    {"name": "db", "image": "postgres:17", "compose_project": "shop"},
    {"name": "debcontrol-app-1", "image": "debcontrol:latest", "compose_project": "debcontrol"},
]


def _machine(**overrides: Any) -> Machine:
    values: dict[str, Any] = {
        "id": uuid.uuid4(),
        "name": "docker1",
        "ip_address": "10.0.0.7",
        "port": 22,
        "username": "root",
        "auth_method": AuthMethod.PASSWORD,
        "host_key_fingerprint": "SHA256:x",
        "docker_status": "ok",
        "docker_containers": CONTAINERS,
    }
    values.update(overrides)
    return Machine(**values)


@pytest.fixture
def own_host(monkeypatch: pytest.MonkeyPatch) -> set[uuid.UUID]:
    """The machine ids debcontrol "runs on" — add one to protect its
    `debcontrol` Compose project."""
    hosts: set[uuid.UUID] = set()

    async def fake_find(_db: Any) -> self_host.SelfHost:
        return self_host.SelfHost(hosts=frozenset(hosts))

    monkeypatch.setattr(self_host, "find", fake_find)
    return hosts


async def _add(db_session_factory: Any, *rows: Any) -> None:
    async with db_session_factory() as db:
        db.add_all(rows)
        await db.commit()


async def _jobs(db_session_factory: Any) -> list[DockerJob]:
    async with db_session_factory() as db:
        result = await db.execute(select(DockerJob).order_by(DockerJob.target))
        return list(result.scalars().all())


def _backup(machine: Machine, **overrides: Any) -> DockerBackup:
    values: dict[str, Any] = {
        "machine_id": machine.id,
        "name": "nightly",
        "repository_encrypted": b"x",
        "password_encrypted": b"x",
        "volumes": ["shop_data", "debcontrol_postgres"],
        "paths": ["/srv/www"],
        "excludes": [],
    }
    values.update(overrides)
    return DockerBackup(**values)


# --- Containers -------------------------------------------------------------------


async def test_update_queues_valid_containers_and_skips_the_rest_with_a_reason(
    db_session_factory: Any, own_host: set[uuid.UUID], celery_calls: RecordedCeleryCalls
) -> None:
    machine = _machine()
    own_host.add(machine.id)
    await _add(db_session_factory, machine)
    async with db_session_factory() as db:
        await docker_jobs.save_container_setting(
            db, machine.id, "db", auto_update=True, gate="high", actor="admin"
        )
        await db.commit()
        queued = await docker_actions.update_containers(
            db,
            machine,
            ["web", "web", "bad name;rm", "debcontrol-app-1", "db"],
            started_by="admin",
        )

    jobs = await _jobs(db_session_factory)
    assert queued.skipped == {"bad name;rm": "invalid", "debcontrol-app-1": "protected"}
    assert [(j.target, j.params) for j in jobs] == [
        ("db", {"gate": "high"}),  # the container's own setting
        ("web", {"gate": "off"}),  # no setting: the gate is off
    ]
    assert all(j.status == DockerJobStatus.PENDING for j in jobs)
    assert len({j.batch_id for j in jobs}) == 1
    # One machine: only its first job is queued; the rest start in turn.
    assert celery_calls.names.count(RUN_JOB) == 1


async def test_an_explicit_gate_overrides_each_containers_setting_and_nothing_is_queued_twice(
    db_session_factory: Any, own_host: set[uuid.UUID], celery_calls: RecordedCeleryCalls
) -> None:
    machine = _machine()
    await _add(db_session_factory, machine)
    async with db_session_factory() as db:
        await docker_jobs.save_container_setting(
            db, machine.id, "db", auto_update=False, gate="worse", actor=None
        )
        await db.commit()
        first = await docker_actions.update_containers(
            db, machine, ["web", "db"], started_by="admin", gate="critical"
        )
        again = await docker_actions.update_containers(
            db, machine, ["web"], started_by="admin", gate="critical"
        )

    assert [j.params for j in first.jobs] == [{"gate": "critical"}, {"gate": "critical"}]
    assert again.jobs == [] and again.skipped == {"web": "already_queued"}
    assert celery_calls.names.count(RUN_JOB) == 1


async def test_saving_a_setting_with_an_unknown_gate_stores_off(db_session_factory: Any) -> None:
    machine = _machine()
    await _add(db_session_factory, machine)
    async with db_session_factory() as db:
        setting = await docker_jobs.save_container_setting(
            db, machine.id, "web", auto_update=True, gate="nonsense", actor="admin"
        )
        await db.commit()
        settings = await docker_jobs.container_settings(db, machine.id)

    assert setting.vulnerability_gate == "off"
    assert settings["web"].auto_update is True


async def test_rollback_needs_a_valid_image_and_refuses_debcontrols_own_containers(
    db_session_factory: Any, own_host: set[uuid.UUID]
) -> None:
    machine = _machine()
    own_host.add(machine.id)
    await _add(db_session_factory, machine)
    async with db_session_factory() as db:
        with pytest.raises(DockerCommandError):
            await docker_actions.rollback_container(
                db, machine, "web", "latest", started_by="admin"
            )
        with pytest.raises(docker_jobs.ProtectedError):
            await docker_actions.rollback_container(
                db, machine, "debcontrol-app-1", IMAGE_ID, started_by="admin"
            )
        job = await docker_actions.rollback_container(
            db, machine, "web", IMAGE_ID, started_by="admin"
        )

    assert job is not None and job.params == {"image_id": IMAGE_ID}
    assert [j.kind for j in await _jobs(db_session_factory)] == ["container_rollback"]


async def test_debcontrols_project_is_not_protected_on_other_machines(
    db_session_factory: Any, own_host: set[uuid.UUID]
) -> None:
    machine = _machine()  # not debcontrol's host
    await _add(db_session_factory, machine)
    async with db_session_factory() as db:
        queued = await docker_actions.update_containers(
            db, machine, ["debcontrol-app-1"], started_by="admin"
        )
    assert queued.skipped == {}
    assert [j.target for j in queued.jobs] == ["debcontrol-app-1"]


def test_own_project_is_found_by_the_container_debcontrol_runs_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    machine = _machine(
        docker_containers=[
            {"id": "0123456789abcdef0000", "name": "dc-web", "compose_project": "renamed"},
            {"id": "ffff", "name": "x", "compose_project": "debcontrol"},
        ]
    )
    own = self_host.SelfHost(hosts=frozenset({machine.id}))
    monkeypatch.setattr("socket.gethostname", lambda: "0123456789AB")

    assert docker_jobs.own_project(machine, own) == "renamed"
    assert docker_jobs.own_project(machine, self_host.NONE) is None


# --- Images, prune ----------------------------------------------------------------


async def test_scan_requests_are_checked_before_queueing(
    db_session_factory: Any, celery_calls: RecordedCeleryCalls
) -> None:
    machine = _machine()
    await _add(db_session_factory, machine)
    async with db_session_factory() as db:
        with pytest.raises(DockerCommandError):
            await docker_actions.scan_images(
                db, machine, started_by="a", images={"nginx;reboot": IMAGE_ID}
            )
        with pytest.raises(DockerCommandError):
            await docker_actions.scan_images(db, machine, started_by="a", scope="everything")
        job = await docker_actions.scan_images(
            db, machine, started_by="a", images={"nginx:1.27": IMAGE_ID, "bad id": "nope"}
        )
        same = await docker_actions.scan_images(
            db, machine, started_by="a", images={"nginx:1.27": IMAGE_ID}
        )

    assert job is not None
    assert job.params == {"images": {"nginx:1.27": IMAGE_ID}}
    assert job.target == "nginx:1.27"
    assert same is None  # already waiting
    assert celery_calls.names.count(RUN_JOB) == 1


async def test_prune_with_nothing_selected_is_refused(db_session_factory: Any) -> None:
    machine = _machine()
    await _add(db_session_factory, machine)
    async with db_session_factory() as db:
        with pytest.raises(DockerCommandError):
            await docker_actions.prune(db, machine, PruneOptions(), started_by="a")
        with pytest.raises(DockerCommandError):
            # "all images" alone selects no prune at all.
            await docker_actions.prune(db, machine, PruneOptions(all_images=True), started_by="a")
    assert await _jobs(db_session_factory) == []


# --- Stacks ------------------------------------------------------------------------


async def test_stack_actions_are_checked_and_debcontrols_project_is_protected(
    db_session_factory: Any, own_host: set[uuid.UUID]
) -> None:
    machine = _machine()
    own_host.add(machine.id)
    await _add(db_session_factory, machine)
    async with db_session_factory() as db:
        with pytest.raises(DockerCommandError):
            await docker_actions.stack_action(db, machine, "Bad Project", "up", started_by="a")
        with pytest.raises(DockerCommandError):
            await docker_actions.stack_action(db, machine, "shop", "explode", started_by="a")
        with pytest.raises(DockerCommandError):  # remove is for managed stacks only
            await docker_actions.stack_action(db, machine, "shop", "remove", started_by="a")
        for action in ("down", "stop", "restart", "update"):
            with pytest.raises(docker_jobs.ProtectedError):
                await docker_actions.stack_action(
                    db, machine, "debcontrol", action, started_by="a"
                )
        started = await docker_actions.stack_action(
            db, machine, "debcontrol", "start", started_by="a"
        )

    assert started is not None and started.params == {"action": "start"}


async def test_up_and_update_of_a_managed_stack_deploy_it_as_stored(
    db_session_factory: Any, own_host: set[uuid.UUID]
) -> None:
    machine = _machine()
    stack = DockerStack(machine_id=machine.id, name="shop", source="editor")
    await _add(db_session_factory, machine, stack)
    async with db_session_factory() as db:
        job = await docker_actions.stack_action(
            db, machine, "shop", "update", started_by="a", stack=stack
        )
    assert job is not None
    assert (job.kind, job.params, job.ref_id) == ("stack_deploy", {"pull": True}, stack.id)


# --- Backups -------------------------------------------------------------------------


async def test_restore_is_checked_before_queueing(
    db_session_factory: Any, own_host: set[uuid.UUID]
) -> None:
    machine = _machine()
    own_host.add(machine.id)
    backup = _backup(machine)
    await _add(db_session_factory, machine, backup)
    async with db_session_factory() as db:
        for snapshot in ("", "../../etc", "ABCDEF12", "abc", "latest; rm -rf /"):
            with pytest.raises(DockerCommandError):
                await docker_actions.restore_backup(
                    db, machine, backup, snapshot, started_by="a",
                    volumes=["shop_data"], paths=[], delete=False,
                )
        with pytest.raises(DockerCommandError):  # nothing of this backup chosen
            await docker_actions.restore_backup(
                db, machine, backup, "latest", started_by="a",
                volumes=["someone_else"], paths=["/etc"], delete=False,
            )
        with pytest.raises(docker_jobs.ProtectedError):
            await docker_actions.restore_backup(
                db, machine, backup, "latest", started_by="a",
                volumes=["debcontrol_postgres"], paths=[], delete=True,
            )
        job = await docker_actions.restore_backup(
            db, machine, backup, "0123abcd", started_by="a",
            volumes=["shop_data", "someone_else"], paths=["/srv/www", "/etc"], delete=True,
        )

    assert job is not None
    assert job.params == {
        "snapshot": "0123abcd",
        "volumes": ["shop_data"],
        "paths": ["/srv/www"],
        "delete": True,
    }


async def test_backup_jobs_are_checked_before_queueing(
    db_session_factory: Any, own_host: set[uuid.UUID]
) -> None:
    machine = _machine()
    own_host.add(machine.id)
    no_retention = _backup(machine, stop_containers=True)
    await _add(db_session_factory, machine, no_retention)
    async with db_session_factory() as db:
        with pytest.raises(DockerCommandError):
            await docker_actions.backup_job(db, machine, no_retention, "delete", started_by="a")
        with pytest.raises(DockerCommandError):
            await docker_actions.backup_job(db, machine, no_retention, "forget", started_by="a")
        # Stopping debcontrol's own containers for a backup would stop the job itself.
        with pytest.raises(docker_jobs.ProtectedError):
            await docker_actions.backup_job(db, machine, no_retention, "run", started_by="a")
        check = await docker_actions.backup_job(
            db, machine, no_retention, "check", started_by="a", read_data_percent=250
        )

    assert check is not None and check.params == {"read_data_percent": 100}


# --- Retention, rollback target ---------------------------------------------------------


async def test_purge_drops_only_old_finished_jobs(db_session_factory: Any) -> None:
    machine = _machine()
    old = datetime.now(UTC) - timedelta(days=docker_jobs.KEEP_DAYS + 1)
    recent = datetime.now(UTC) - timedelta(days=1)

    def job(target: str, status: DockerJobStatus, created: datetime) -> DockerJob:
        return DockerJob(
            machine_id=machine.id, kind="prune", target=target, status=status, created_at=created
        )

    await _add(
        db_session_factory,
        machine,
        job("old-done", DockerJobStatus.SUCCEEDED, old),
        job("old-blocked", DockerJobStatus.BLOCKED, old),
        job("old-running", DockerJobStatus.RUNNING, old),
        job("old-pending", DockerJobStatus.PENDING, old),
        job("recent-failed", DockerJobStatus.FAILED, recent),
    )
    async with db_session_factory() as db:
        removed = await docker_jobs.purge_old(db)

    assert removed == 2
    assert [j.target for j in await _jobs(db_session_factory)] == [
        "old-pending",
        "old-running",
        "recent-failed",
    ]


def test_rollback_goes_back_from_the_newest_successful_update() -> None:
    machine_id = uuid.uuid4()

    def job(kind: str, status: str, previous: str, target: str = "web") -> DockerJob:
        return DockerJob(
            machine_id=machine_id,
            kind=kind,
            target=target,
            status=status,
            result={"previous_image_id": previous},
        )

    newest_first = [
        job("container_update", "blocked", "sha256:blocked"),
        job("container_update", "succeeded", "sha256:other", target="db"),
        job("container_update", "succeeded", IMAGE_ID),
        job("container_update", "succeeded", "sha256:older"),
    ]
    found = docker_jobs.last_update(newest_first, "web")
    assert docker_jobs.rollback_image(found) == IMAGE_ID
    assert docker_jobs.rollback_image(None) is None
    assert docker_jobs.last_update(newest_first, "cache") is None


def test_output_keeps_the_tail() -> None:
    text = "x" * docker_jobs.MAX_OUTPUT_CHARS + "END"
    kept = docker_jobs.truncate_output(text)
    assert len(kept) == docker_jobs.MAX_OUTPUT_CHARS and kept.endswith("END")


# --- Scheduled actions ------------------------------------------------------------------


async def _run_action(
    db_session_factory: Any, key: str, machines: list[Machine], params: dict[str, str]
) -> Any:
    register_builtin_actions()
    spec = get_action(key)
    assert spec is not None
    async with db_session_factory() as db:
        return await spec.run(db, machines, params)


@pytest.mark.parametrize("level", ["safe", "images", "volumes", "", "all_volumes", "anything"])
async def test_a_scheduled_cleanup_never_removes_named_volumes(
    db_session_factory: Any, level: str
) -> None:
    machine = _machine()
    await _add(db_session_factory, machine)

    result = await _run_action(
        db_session_factory, "docker_prune", [machine], {"docker_prune_level": level}
    )

    (job,) = await _jobs(db_session_factory)
    assert result.attempted == 1
    assert job.started_by == "schedule"
    assert job.params is not None and job.params["all_volumes"] is False
    assert job.params["volumes"] is (level == "volumes")


async def test_scheduled_actions_skip_machines_without_readable_docker_or_host_key(
    db_session_factory: Any,
) -> None:
    ready = _machine()
    no_docker = _machine(name="b", docker_status="no_access")
    no_key = _machine(name="c", host_key_fingerprint=None)
    await _add(db_session_factory, ready, no_docker, no_key)

    result = await _run_action(
        db_session_factory, "docker_scan", [ready, no_docker, no_key],
        {"docker_scan_scope": "every"},
    )

    (job,) = await _jobs(db_session_factory)
    assert (result.attempted, result.skipped) == (1, 2)
    assert job.machine_id == ready.id
    # "every" in the form is the "all" scope.
    assert job.params == {"scope": "all"}


async def test_scheduled_update_picks_containers_by_scope_and_gate_by_setting(
    db_session_factory: Any, own_host: set[uuid.UUID]
) -> None:
    machine = _machine(docker_image_updates={"nginx:1.27": "update", "postgres:17": "current"})
    await _add(db_session_factory, machine)
    async with db_session_factory() as db:
        await docker_jobs.save_container_setting(
            db, machine.id, "db", auto_update=True, gate="high", actor=None
        )
        await db.commit()

    auto = await _run_action(
        db_session_factory, "docker_update", [machine],
        {"docker_scope": "auto", "docker_gate": "setting"},
    )
    assert auto.attempted == 1
    assert [(j.target, j.params) for j in await _jobs(db_session_factory)] == [
        ("db", {"gate": "high"})
    ]

    with_update = await _run_action(
        db_session_factory, "docker_update", [machine],
        {"docker_scope": "with_update", "docker_gate": "critical"},
    )
    assert with_update.attempted == 1
    assert [(j.target, j.params) for j in await _jobs(db_session_factory)] == [
        ("db", {"gate": "high"}),
        ("web", {"gate": "critical"}),
    ]


async def test_scheduled_backup_prune_skips_disabled_backups_and_those_without_retention(
    db_session_factory: Any, own_host: set[uuid.UUID]
) -> None:
    machine = _machine()
    keeps = _backup(machine, name="keeps", keep_daily=7)
    keeps_all = _backup(machine, name="keeps-all")
    disabled = _backup(machine, name="disabled", keep_daily=7, enabled=False)
    await _add(db_session_factory, machine, keeps, keeps_all, disabled)

    result = await _run_action(db_session_factory, "docker_backup_prune", [machine], {})

    assert result.attempted == 1
    assert [(j.kind, j.target) for j in await _jobs(db_session_factory)] == [
        (DockerJobKind.BACKUP_FORGET, "keeps")
    ]


async def test_scheduled_backup_skips_a_protected_one_and_counts_per_machine(
    db_session_factory: Any, own_host: set[uuid.UUID]
) -> None:
    machine = _machine()
    own_host.add(machine.id)
    safe = _backup(machine, name="shop", volumes=["shop_data"], stop_containers=True)
    own = _backup(machine, name="own", stop_containers=True)  # stops debcontrol's volume users
    await _add(db_session_factory, machine, safe, own)

    result = await _run_action(db_session_factory, "docker_backup", [machine], {})

    # Counted per machine, like every other action: one of its backups ran.
    assert (result.attempted, result.skipped) == (1, 0)
    assert [j.target for j in await _jobs(db_session_factory)] == ["shop"]
