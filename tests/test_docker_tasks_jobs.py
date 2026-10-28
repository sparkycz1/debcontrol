"""The Docker job runner (`app.tasks.docker_jobs`): container updates and
the vulnerability gate end to end, one job at a time per machine, resuming
and reconciling jobs, backups, stacks, scans and Git auto-sync — with the
SSH side replaced by a scripted fake machine.

As everywhere else, the underscore-prefixed coroutines are called directly,
never the Celery wrappers."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy import select

from app.db.models.docker import (
    DockerBackup,
    DockerImageScan,
    DockerJob,
    DockerJobKind,
    DockerJobStatus,
    DockerStack,
)
from app.db.models.machine import AuthMethod, Machine
from app.db.models.notification_rule import NotificationEventType
from app.services import docker_stacks, self_host
from app.services.docker_jobs import PROTECTED_MESSAGE
from app.ssh import detached_jobs
from app.ssh.detached_jobs import FollowResult
from app.ssh.docker_cli import CommandOutput, DockerAccessError
from app.ssh.docker_update import build_retag_command
from app.tasks import docker_jobs as tasks
from tests.conftest import RecordedCeleryCalls

OLD_ID = "sha256:" + "a" * 64
NEW_ID = "sha256:" + "b" * 64
COMMIT = "1" * 40
NEW_COMMIT = "2" * 40
RUN_JOB = "app.tasks.docker_jobs.run_docker_job"
SAMPLE = "app.tasks.jobs.sample_machine_monitoring"
IMAGE_CHECK = "app.tasks.jobs.check_machine_image_updates"


@dataclass
class FakeMachine:
    """What the job runner sees of the machine over SSH."""

    # Answers to the detached phases, in order (`detached_jobs.follow`).
    follows: list[FollowResult] = field(default_factory=list)
    # (remote id, script) of every detached job started.
    started: list[tuple[str, str]] = field(default_factory=list)
    # Every short script run (`run_script`), and what to answer.
    short: list[str] = field(default_factory=list)
    answers: list[tuple[str, CommandOutput]] = field(default_factory=list)
    notified: list[tuple[NotificationEventType, dict[str, Any]]] = field(default_factory=list)
    inventory: Any = None

    def answer(self, needle: str, output: str, exit_status: int = 0) -> None:
        self.answers.append((needle, CommandOutput(exit_status, output)))

    def finishes(self, output: str, exit_status: int = 0) -> None:
        self.follows.append(FollowResult("finished", exit_status, output))


@pytest.fixture
def machine_shell(monkeypatch: pytest.MonkeyPatch, db_session_factory: Any) -> FakeMachine:
    fake = FakeMachine()
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)

    async def fake_credential(*_args: Any) -> None:
        return None

    async def fake_publish(*_args: Any) -> None:
        return None

    async def fake_notify(
        _session: Any, event: NotificationEventType, **kwargs: Any
    ) -> None:
        fake.notified.append((event, dict(kwargs.get("context") or {})))

    async def fake_start(
        _machine: Any, _secret: Any, _area: str, remote: str, script: str, _timeout: int
    ) -> bool:
        fake.started.append((remote, script))
        return True

    async def fake_follow(*_args: Any, **_kwargs: Any) -> FollowResult:
        assert fake.follows, "a detached phase was followed that the test did not expect"
        return fake.follows.pop(0)

    async def fake_run_script(
        _machine: Any, _secret: Any, _timeout: int, script: str, **_kwargs: Any
    ) -> CommandOutput:
        fake.short.append(script)
        for needle, output in fake.answers:
            if needle in script:
                return output
        return CommandOutput(0, "")

    async def fake_inventory(*_args: Any, **_kwargs: Any) -> Any:
        if fake.inventory is None:
            raise DockerAccessError("no access")
        return fake.inventory

    monkeypatch.setattr(tasks, "resolve_machine_credential", fake_credential)
    monkeypatch.setattr(tasks, "publish_machine_event", fake_publish)
    monkeypatch.setattr(tasks, "notify", fake_notify)
    monkeypatch.setattr(tasks, "run_script", fake_run_script)
    monkeypatch.setattr(tasks, "read_inventory", fake_inventory)
    monkeypatch.setattr(detached_jobs, "start", fake_start)
    monkeypatch.setattr(detached_jobs, "follow", fake_follow)
    return fake


@pytest.fixture
def own_host(monkeypatch: pytest.MonkeyPatch) -> set[uuid.UUID]:
    hosts: set[uuid.UUID] = set()

    async def fake_find(_db: Any) -> self_host.SelfHost:
        return self_host.SelfHost(hosts=frozenset(hosts))

    monkeypatch.setattr(self_host, "find", fake_find)
    return hosts


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
        "docker_containers": [
            {"name": "web", "image": "nginx:1.27", "compose_project": "shop"},
            {"name": "debcontrol-app-1", "compose_project": "debcontrol"},
        ],
    }
    values.update(overrides)
    return Machine(**values)


async def _add(db_session_factory: Any, *rows: Any) -> None:
    async with db_session_factory() as db:
        db.add_all(rows)
        await db.commit()


def _job(machine: Machine, kind: str, target: str, **overrides: Any) -> DockerJob:
    values: dict[str, Any] = {
        "id": uuid.uuid4(),
        "machine_id": machine.id,
        "kind": kind,
        "target": target,
        "params": {},
        "started_by": "admin",
    }
    values.update(overrides)
    return DockerJob(**values)


async def _get(db_session_factory: Any, model: Any, row_id: uuid.UUID) -> Any:
    async with db_session_factory() as db:
        return await db.get(model, row_id)


# --- Container updates and the vulnerability gate ---------------------------------


def _inspect_output(ref: str = "nginx:1.27") -> str:
    labels = {
        "com.docker.compose.project": "shop",
        "com.docker.compose.service": "web",
        "com.docker.compose.project.working_dir": "/srv/shop",
        "com.docker.compose.project.config_files": "/srv/shop/compose.yaml",
    }
    container = {
        "Name": "/web",
        "Id": "c0ffee",
        "Image": OLD_ID,
        "Config": {"Image": ref, "Labels": labels},
        "State": {"Running": True},
    }
    image = {"RepoDigests": ["nginx@sha256:" + "d" * 64]}
    return json.dumps([container]) + "\n@@DC_SPLIT\n" + json.dumps([image])


def _scan_lines(image: str, findings: list[str], *, failed: bool = False) -> str:
    status = "1" if failed else "0"
    lines = ["@@DC_SCANNER trivy 0.58.1", f"@@DC_IMAGE {image}", "@@DC_BEGIN trivy"]
    lines += [f"V\t{vuln_id}\topenssl\t3.0.1\t3.0.2\t{severity}\t\tTitle"
              for vuln_id, severity in (f.split(":") for f in findings)]
    lines += [f"@@DC_END trivy {status}", "@@DC_BEGIN grype", f"@@DC_END grype {status}"]
    return "\n".join(lines) + "\n"


def _pull_output(new_id: str = NEW_ID, scan: str = "") -> str:
    return f"@@DC_OLD_ID {OLD_ID}\nPulling...\n@@DC_NEW_ID {new_id}\n" + scan


async def _update_job(db_session_factory: Any, gate: str) -> tuple[Machine, DockerJob]:
    machine = _machine()
    job = _job(machine, DockerJobKind.CONTAINER_UPDATE, "web", params={"gate": gate})
    await _add(db_session_factory, machine, job)
    return machine, job


async def test_gate_blocks_an_update_whose_new_image_has_a_critical_vulnerability(
    db_session_factory: Any, machine_shell: FakeMachine, celery_calls: RecordedCeleryCalls
) -> None:
    _machine_row, job = await _update_job(db_session_factory, "critical")
    machine_shell.answer("inspect --type container", _inspect_output())
    machine_shell.finishes(
        _pull_output(scan=_scan_lines("nginx:1.27", ["CVE-2024-0001:CRITICAL"]))
    )

    await tasks._run_docker_job(str(job.id))

    stored = await _get(db_session_factory, DockerJob, job.id)
    assert stored.status == DockerJobStatus.BLOCKED
    assert stored.error.startswith("Stopped by the vulnerability gate (critical)")
    assert stored.result["gate"]["allowed"] is False
    assert stored.result["gate"]["new"]["critical"] == 1
    # Pulled (and scanned) only: the container was never recreated.
    assert [remote for remote, _ in machine_shell.started] == [
        tasks.remote_id(job.id, "pull")
    ]
    assert "trivy" in machine_shell.started[0][1]
    # The tag points at the running image again.
    assert build_retag_command(OLD_ID, "nginx:1.27") in machine_shell.short
    assert machine_shell.notified == [
        (NotificationEventType.DOCKER_UPDATE_BLOCKED, {"container": "web", "details": stored.error})
    ]
    async with db_session_factory() as db:
        scans = (await db.execute(select(DockerImageScan))).scalars().all()
    assert [s.image_id for s in scans] == [NEW_ID]
    assert SAMPLE in celery_calls.names and IMAGE_CHECK not in celery_calls.names


async def test_gate_fails_closed_when_the_scanners_could_not_scan_the_new_image(
    db_session_factory: Any, machine_shell: FakeMachine
) -> None:
    _machine_row, job = await _update_job(db_session_factory, "high")
    machine_shell.answer("inspect --type container", _inspect_output())
    machine_shell.finishes(_pull_output(scan=_scan_lines("nginx:1.27", [], failed=True)))

    await tasks._run_docker_job(str(job.id))

    stored = await _get(db_session_factory, DockerJob, job.id)
    assert stored.status == DockerJobStatus.BLOCKED
    assert stored.result["gate"]["reason"] == "not_scanned"
    assert len(machine_shell.started) == 1


async def test_worse_gate_compares_with_the_stored_scan_of_the_running_image(
    db_session_factory: Any, machine_shell: FakeMachine
) -> None:
    machine = _machine()
    old_scan = DockerImageScan(
        machine_id=machine.id,
        image_id=OLD_ID,
        image_ref="nginx:1.26",
        counts={"critical": 0, "high": 1, "medium": 0, "low": 0, "unknown": 0},
    )
    await _add(db_session_factory, machine, old_scan)
    job = _job(machine, DockerJobKind.CONTAINER_UPDATE, "web", params={"gate": "worse"})
    await _add(db_session_factory, job)
    machine_shell.answer("inspect --type container", _inspect_output())
    machine_shell.finishes(
        _pull_output(scan=_scan_lines("nginx:1.27", ["CVE-1:HIGH", "CVE-2:CRITICAL"]))
    )

    await tasks._run_docker_job(str(job.id))

    stored = await _get(db_session_factory, DockerJob, job.id)
    assert stored.status == DockerJobStatus.BLOCKED
    assert stored.result["gate"]["reason"] == "worse"
    assert stored.result["gate"]["old"]["high"] == 1


async def test_update_without_a_gate_pulls_recreates_and_reports_success(
    db_session_factory: Any, machine_shell: FakeMachine, celery_calls: RecordedCeleryCalls
) -> None:
    _machine_row, job = await _update_job(db_session_factory, "off")
    machine_shell.answer("inspect --type container", _inspect_output())
    machine_shell.finishes(_pull_output())
    machine_shell.finishes("Recreating web...\n@@DC_DONE\n")

    await tasks._run_docker_job(str(job.id))

    stored = await _get(db_session_factory, DockerJob, job.id)
    assert stored.status == DockerJobStatus.SUCCEEDED
    assert stored.error is None and stored.finished_at is not None
    assert stored.result["previous_image_id"] == OLD_ID
    assert stored.result["new_image_id"] == NEW_ID
    assert stored.result["phases"] == ["pull", "recreate"]
    assert "trivy" not in machine_shell.started[0][1]  # no gate: no scan
    assert "@@DC_DONE" in stored.output
    assert [e for e, _ in machine_shell.notified] == [NotificationEventType.DOCKER_UPDATE_SUCCEEDED]
    assert IMAGE_CHECK in celery_calls.names


async def test_update_to_the_same_image_is_skipped_without_a_notification(
    db_session_factory: Any, machine_shell: FakeMachine
) -> None:
    _machine_row, job = await _update_job(db_session_factory, "critical")
    machine_shell.answer("inspect --type container", _inspect_output())
    machine_shell.finishes(_pull_output(new_id=OLD_ID))

    await tasks._run_docker_job(str(job.id))

    stored = await _get(db_session_factory, DockerJob, job.id)
    assert stored.status == DockerJobStatus.SKIPPED
    assert stored.result["note"] == "up_to_date"
    assert len(machine_shell.started) == 1
    assert machine_shell.notified == []


async def test_a_new_container_that_does_not_stay_up_is_put_back_and_reported(
    db_session_factory: Any, machine_shell: FakeMachine
) -> None:
    _machine_row, job = await _update_job(db_session_factory, "off")
    machine_shell.answer("inspect --type container", _inspect_output())
    machine_shell.finishes(_pull_output())
    machine_shell.finishes("@@DC_FAILED settle\n@@DC_RESTORE\n", exit_status=1)

    await tasks._run_docker_job(str(job.id))

    stored = await _get(db_session_factory, DockerJob, job.id)
    assert stored.status == DockerJobStatus.FAILED
    assert "previous one was put back" in stored.error
    assert stored.result["restored"] is True
    assert [e for e, _ in machine_shell.notified] == [NotificationEventType.DOCKER_UPDATE_FAILED]


async def test_a_container_pinned_to_a_digest_is_not_updated(
    db_session_factory: Any, machine_shell: FakeMachine
) -> None:
    _machine_row, job = await _update_job(db_session_factory, "off")
    machine_shell.answer(
        "inspect --type container", _inspect_output(ref="nginx@sha256:" + "e" * 64)
    )

    await tasks._run_docker_job(str(job.id))

    stored = await _get(db_session_factory, DockerJob, job.id)
    assert stored.status == DockerJobStatus.FAILED
    assert "fixed image" in stored.error
    assert machine_shell.started == []


# --- One job at a time, claimed once -------------------------------------------------


async def test_a_job_waits_while_another_runs_on_the_same_machine(
    db_session_factory: Any, machine_shell: FakeMachine
) -> None:
    machine = _machine()
    running = _job(machine, DockerJobKind.PRUNE, "prune", status=DockerJobStatus.RUNNING)
    waiting = _job(machine, DockerJobKind.PRUNE, "other", params={"images": True})
    await _add(db_session_factory, machine, running, waiting)

    await tasks._run_docker_job(str(waiting.id))

    stored = await _get(db_session_factory, DockerJob, waiting.id)
    assert stored.status == DockerJobStatus.PENDING
    assert stored.started_at is None
    assert machine_shell.started == []


async def test_a_job_runs_once_and_then_starts_the_machines_next_one(
    db_session_factory: Any, machine_shell: FakeMachine, celery_calls: RecordedCeleryCalls
) -> None:
    machine = _machine()
    elsewhere = _machine(name="docker2", ip_address="10.0.0.8")
    now = datetime.now(UTC)
    first = _job(machine, DockerJobKind.PRUNE, "prune", params={"images": True},
                 created_at=now - timedelta(minutes=3))
    second = _job(machine, DockerJobKind.PRUNE, "prune-2", params={"images": True},
                  created_at=now - timedelta(minutes=2))
    other_machine = _job(elsewhere, DockerJobKind.PRUNE, "prune", params={"images": True},
                         created_at=now - timedelta(minutes=4))
    await _add(db_session_factory, machine, elsewhere, first, second, other_machine)
    machine_shell.finishes("@@DC_PRUNE images\nTotal reclaimed space: 1.5GB\n")

    await tasks._run_docker_job(str(first.id))
    await tasks._run_docker_job(str(first.id))  # queued twice: runs once

    stored = await _get(db_session_factory, DockerJob, first.id)
    assert stored.status == DockerJobStatus.SUCCEEDED
    assert stored.result["reclaimed_bytes"] > 1_000_000_000
    assert len(machine_shell.started) == 1
    queued = [args[0] for name, args, _ in celery_calls if name == RUN_JOB]
    assert queued == [str(second.id)]


async def test_a_job_without_a_pinned_host_key_fails_without_touching_the_machine(
    db_session_factory: Any, machine_shell: FakeMachine
) -> None:
    machine = _machine(host_key_fingerprint=None)
    job = _job(machine, DockerJobKind.PRUNE, "prune", params={"images": True})
    await _add(db_session_factory, machine, job)

    await tasks._run_docker_job(str(job.id))

    stored = await _get(db_session_factory, DockerJob, job.id)
    assert (stored.status, stored.error) == (
        DockerJobStatus.FAILED,
        "No pinned host key fingerprint yet.",
    )
    assert machine_shell.started == []


async def test_an_unreachable_machine_leaves_the_job_running_for_the_next_sweep(
    db_session_factory: Any, machine_shell: FakeMachine
) -> None:
    machine = _machine()
    job = _job(machine, DockerJobKind.PRUNE, "prune", params={"images": True})
    await _add(db_session_factory, machine, job)
    machine_shell.follows.append(FollowResult("unreachable", None, "", "timed out"))

    with pytest.raises(tasks._TryLaterError):
        await tasks._run_docker_job(str(job.id))

    stored = await _get(db_session_factory, DockerJob, job.id)
    assert stored.status == DockerJobStatus.RUNNING
    assert stored.result["phase"] == "run"


async def test_a_job_lost_on_the_machine_fails(
    db_session_factory: Any, machine_shell: FakeMachine
) -> None:
    machine = _machine()
    job = _job(machine, DockerJobKind.PRUNE, "prune", params={"images": True})
    await _add(db_session_factory, machine, job)
    machine_shell.follows.append(FollowResult("lost", None, "partial"))

    await tasks._run_docker_job(str(job.id))

    stored = await _get(db_session_factory, DockerJob, job.id)
    assert stored.status == DockerJobStatus.FAILED
    assert "stopped on the machine" in stored.error


async def test_a_resumed_job_follows_the_phase_it_started_instead_of_starting_it_again(
    db_session_factory: Any, machine_shell: FakeMachine
) -> None:
    machine = _machine()
    beat = datetime.now(UTC) - timedelta(minutes=5)
    job = _job(
        machine,
        DockerJobKind.PRUNE,
        "prune",
        params={"images": True},
        status=DockerJobStatus.RUNNING,
        started_at=beat,
        heartbeat_at=beat,
        result={"phase": "run", "phases": ["run"]},
        output="before restart\n",
    )
    await _add(db_session_factory, machine, job)
    machine_shell.finishes("Total reclaimed space: 0B\n")

    # A sweep that saw a different heartbeat does not take it.
    await tasks._resume_docker_job(str(job.id), (beat + timedelta(seconds=1)).isoformat())
    assert (await _get(db_session_factory, DockerJob, job.id)).status == DockerJobStatus.RUNNING

    await tasks._resume_docker_job(str(job.id), beat.isoformat())

    stored = await _get(db_session_factory, DockerJob, job.id)
    assert stored.status == DockerJobStatus.SUCCEEDED
    assert machine_shell.started == []
    assert stored.output.startswith("before restart\n")
    assert tasks.RESUMED_NOTE in stored.output


async def test_reconcile_resumes_stale_jobs_kicks_forgotten_ones_and_gives_up_on_old_ones(
    db_session_factory: Any, machine_shell: FakeMachine, celery_calls: RecordedCeleryCalls
) -> None:
    now = datetime.now(UTC)
    stale_machine = _machine(name="a")
    idle_machine = _machine(name="b")
    fresh_machine = _machine(name="c")
    stale = _job(stale_machine, DockerJobKind.PRUNE, "stale", status=DockerJobStatus.RUNNING,
                 heartbeat_at=now - timedelta(minutes=10))
    behind_stale = _job(stale_machine, DockerJobKind.PRUNE, "behind",
                        created_at=now - timedelta(minutes=5))
    forgotten = _job(idle_machine, DockerJobKind.PRUNE, "forgotten",
                     created_at=now - timedelta(minutes=5))
    ancient = _job(idle_machine, DockerJobKind.PRUNE, "ancient",
                   created_at=now - timedelta(hours=25))
    just_queued = _job(fresh_machine, DockerJobKind.PRUNE, "new", created_at=now)
    await _add(
        db_session_factory, stale_machine, idle_machine, fresh_machine,
        stale, behind_stale, forgotten, ancient, just_queued,
    )

    counts = await tasks._reconcile_docker_jobs()
    again = await tasks._reconcile_docker_jobs()

    assert counts == {"resumed": 1, "kicked": 1, "abandoned": 1}
    # The resumed job's heartbeat was just renewed; the kicked one is not nudged twice.
    assert again == {"resumed": 0, "kicked": 0, "abandoned": 0}
    resumed = [args for name, args, _ in celery_calls if name.endswith("resume_docker_job")]
    kicked = [args[0] for name, args, _ in celery_calls if name == RUN_JOB]
    assert [args[0] for args in resumed] == [str(stale.id)]
    assert kicked == [str(forgotten.id)]
    gave_up = await _get(db_session_factory, DockerJob, ancient.id)
    assert gave_up.status == DockerJobStatus.FAILED and "never started" in gave_up.error


# --- Backups ---------------------------------------------------------------------------


def _backup(machine: Machine, **overrides: Any) -> DockerBackup:
    from app.core.security import encrypt_secret

    values: dict[str, Any] = {
        "id": uuid.uuid4(),
        "machine_id": machine.id,
        "name": "nightly",
        "repository_encrypted": encrypt_secret("/srv/backup"),
        "password_encrypted": encrypt_secret("restic-password-456"),
        "volumes": ["shop_data", "debcontrol_postgres"],
        "paths": [],
        "excludes": [],
    }
    values.update(overrides)
    return DockerBackup(**values)


async def test_a_successful_backup_records_its_snapshot(
    db_session_factory: Any, machine_shell: FakeMachine
) -> None:
    machine = _machine()
    backup = _backup(machine)
    job = _job(machine, DockerJobKind.BACKUP_RUN, "nightly", ref_id=backup.id)
    await _add(db_session_factory, machine, backup, job)
    summary = {
        "message_type": "summary",
        "snapshot_id": "0123abcd" * 8,
        "data_added": 2048,
        "total_bytes_processed": 4096,
        "files_new": 3,
    }
    machine_shell.finishes(json.dumps(summary) + "\n")

    await tasks._run_docker_job(str(job.id))

    stored_job = await _get(db_session_factory, DockerJob, job.id)
    stored = await _get(db_session_factory, DockerBackup, backup.id)
    refreshed = await _get(db_session_factory, Machine, machine.id)
    assert stored_job.status == DockerJobStatus.SUCCEEDED
    assert stored.last_backup_status == "ok"
    assert stored.last_snapshot_id == "0123abcd" * 8
    assert stored.last_backup_bytes == 2048
    assert refreshed.docker_backup_ok_at is not None
    # The password reaches the machine only inside the script, on standard input.
    assert "restic-password-456" in machine_shell.started[0][1]
    for kept in (str(stored_job.params), str(stored_job.result), stored_job.output or ""):
        assert "restic-password-456" not in kept
    assert machine_shell.notified == []


async def test_a_failed_backup_is_recorded_and_notified(
    db_session_factory: Any, machine_shell: FakeMachine
) -> None:
    machine = _machine()
    backup = _backup(machine)
    job = _job(machine, DockerJobKind.BACKUP_RUN, "nightly", ref_id=backup.id)
    await _add(db_session_factory, machine, backup, job)
    machine_shell.finishes("Fatal: unable to open repository\n", exit_status=1)

    await tasks._run_docker_job(str(job.id))

    stored = await _get(db_session_factory, DockerBackup, backup.id)
    assert stored.last_backup_status == "failed"
    assert stored.last_success_at is None
    assert machine_shell.notified == [
        (
            NotificationEventType.DOCKER_BACKUP_FAILED,
            {"backup": "nightly", "details": "The backup failed — see the output."},
        )
    ]


async def test_restoring_onto_debcontrols_own_volumes_fails_before_anything_runs(
    db_session_factory: Any, machine_shell: FakeMachine, own_host: set[uuid.UUID]
) -> None:
    machine = _machine()
    own_host.add(machine.id)
    backup = _backup(machine)
    job = _job(
        machine,
        DockerJobKind.BACKUP_RESTORE,
        "nightly",
        ref_id=backup.id,
        params={"snapshot": "latest", "volumes": ["debcontrol_postgres"], "paths": []},
    )
    await _add(db_session_factory, machine, backup, job)

    await tasks._run_docker_job(str(job.id))

    stored = await _get(db_session_factory, DockerJob, job.id)
    assert (stored.status, stored.error) == (DockerJobStatus.FAILED, PROTECTED_MESSAGE)
    assert machine_shell.started == []


async def test_restoring_into_a_volume_runs_the_restore_to_script(
    db_session_factory: Any, machine_shell: FakeMachine
) -> None:
    machine = _machine()
    backup = _backup(machine)
    job = _job(
        machine,
        DockerJobKind.BACKUP_RESTORE,
        "nightly",
        ref_id=backup.id,
        params={"mode": "to", "snapshot": "latest", "source": "/backup/volumes/old",
                "volume": "fresh", "path": "", "delete": False},
    )
    await _add(db_session_factory, machine, backup, job)
    machine_shell.finishes("@@DC_DONE\n")

    await tasks._run_docker_job(str(job.id))

    [(_remote, script)] = machine_shell.started
    assert "-v fresh:/restore" in script
    assert "R restore latest:/backup/volumes/old --target /restore ||" in script
    assert (await _get(db_session_factory, DockerJob, job.id)).status == DockerJobStatus.SUCCEEDED


async def test_a_job_whose_backup_was_deleted_fails(
    db_session_factory: Any, machine_shell: FakeMachine
) -> None:
    machine = _machine()
    job = _job(machine, DockerJobKind.BACKUP_CHECK, "gone", ref_id=uuid.uuid4())
    await _add(db_session_factory, machine, job)

    await tasks._run_docker_job(str(job.id))

    stored = await _get(db_session_factory, DockerJob, job.id)
    assert (stored.status, stored.error) == (DockerJobStatus.FAILED, "The backup was deleted.")


# --- Stacks -------------------------------------------------------------------------------


def _stack(machine: Machine, **overrides: Any) -> DockerStack:
    values: dict[str, Any] = {
        "id": uuid.uuid4(),
        "machine_id": machine.id,
        "name": "shop",
        "source": "editor",
        "compose_content": "services:\n  web:\n    image: nginx:1.27\n",
    }
    values.update(overrides)
    return DockerStack(**values)


async def test_a_deployed_stack_remembers_what_was_deployed(
    db_session_factory: Any, machine_shell: FakeMachine
) -> None:
    machine = _machine()
    stack = _stack(machine)
    job = _job(machine, DockerJobKind.STACK_DEPLOY, "shop", ref_id=stack.id, params={"pull": True})
    await _add(db_session_factory, machine, stack, job)
    machine_shell.finishes("Container shop-web-1 Started\n@@DC_DONE\n")

    await tasks._run_docker_job(str(job.id))

    stored = await _get(db_session_factory, DockerStack, stack.id)
    assert (await _get(db_session_factory, DockerJob, job.id)).status == DockerJobStatus.SUCCEEDED
    assert stored.last_status == "ok" and stored.deployed_at is not None
    assert stored.deployed_hash == docker_stacks.content_hash(stored)
    assert not docker_stacks.is_changed(stored)


async def test_a_failed_deployment_is_recorded_and_notified(
    db_session_factory: Any, machine_shell: FakeMachine
) -> None:
    machine = _machine()
    stack = _stack(machine)
    job = _job(machine, DockerJobKind.STACK_DEPLOY, "shop", ref_id=stack.id)
    await _add(db_session_factory, machine, stack, job)
    machine_shell.finishes("@@DC_FAILED config\n", exit_status=1)

    await tasks._run_docker_job(str(job.id))

    stored = await _get(db_session_factory, DockerStack, stack.id)
    assert stored.last_status == "failed"
    assert stored.deployed_hash is None
    assert 'step "config"' in stored.last_error
    assert [(e, c["stack"]) for e, c in machine_shell.notified] == [
        (NotificationEventType.DOCKER_STACK_FAILED, "shop")
    ]


async def test_removing_a_managed_stack_deletes_it_once_compose_is_done(
    db_session_factory: Any, machine_shell: FakeMachine
) -> None:
    machine = _machine()
    stack = _stack(machine)
    job = _job(
        machine, DockerJobKind.STACK_ACTION, "shop", ref_id=stack.id,
        params={"action": "remove", "volumes": False},
    )
    await _add(db_session_factory, machine, stack, job)
    machine_shell.finishes("removed\n")

    await tasks._run_docker_job(str(job.id))

    assert await _get(db_session_factory, DockerStack, stack.id) is None
    assert (await _get(db_session_factory, DockerJob, job.id)).status == DockerJobStatus.SUCCEEDED


async def test_removing_a_stack_in_a_chosen_directory_keeps_that_directory(
    db_session_factory: Any, machine_shell: FakeMachine
) -> None:
    machine = _machine()
    stack = _stack(machine)
    stack.directory = "/opt/shop"
    job = _job(
        machine, DockerJobKind.STACK_ACTION, "shop", ref_id=stack.id,
        params={"action": "remove", "volumes": False},
    )
    await _add(db_session_factory, machine, stack, job)
    machine_shell.finishes("@@DC_DONE\n")

    await tasks._run_docker_job(str(job.id))

    [(_remote, script)] = machine_shell.started
    assert "dir=/opt/shop;" in script
    assert 'rm -rf -- "$dir";' not in script
    assert await _get(db_session_factory, DockerStack, stack.id) is None


async def test_git_sync_deploys_only_a_new_commit_and_never_twice(
    db_session_factory: Any, machine_shell: FakeMachine, celery_calls: RecordedCeleryCalls
) -> None:
    machine = _machine()
    stack = _stack(
        machine,
        source="git",
        compose_content=None,
        git_url="https://git.example.com/me/shop.git",
        git_branch="main",
        git_compose_path="compose.yaml",
        deployed_commit=COMMIT,
    )
    stack.deployed_hash = docker_stacks.content_hash(stack)
    await _add(db_session_factory, machine, stack)

    machine_shell.answer("ls-remote", f"@@DC_COMMIT {COMMIT}\n")
    unchanged = await tasks._sync_git_stack(str(stack.id), started_by="Git auto-sync")
    machine_shell.answers.clear()
    machine_shell.answer("", f"@@DC_COMMIT {NEW_COMMIT}\n")
    first = await tasks._sync_git_stack(str(stack.id), started_by="Git auto-sync")
    second = await tasks._sync_git_stack(str(stack.id), started_by="Git auto-sync")

    assert unchanged == {"ok": True, "deployed": False, "commit": COMMIT}
    assert first == {"ok": True, "deployed": True, "commit": NEW_COMMIT}
    assert second == {"ok": True, "deployed": False, "commit": NEW_COMMIT}
    async with db_session_factory() as db:
        jobs = (await db.execute(select(DockerJob))).scalars().all()
    assert [(j.kind, j.ref_id, j.started_by) for j in jobs] == [
        (DockerJobKind.STACK_DEPLOY, stack.id, "Git auto-sync")
    ]
    assert celery_calls.names.count(RUN_JOB) == 1


async def test_git_poll_enqueues_one_sync_per_auto_synced_stack_on_active_machines(
    db_session_factory: Any, machine_shell: FakeMachine, celery_calls: RecordedCeleryCalls
) -> None:
    active = _machine()
    retired = _machine(name="old", is_active=False)
    synced = _stack(active, name="synced", source="git", git_url="https://g.example/x.git",
                    auto_sync=True)
    manual = _stack(active, name="manual", source="git", git_url="https://g.example/y.git")
    editor = _stack(active, name="editor", auto_sync=True)
    on_retired = _stack(retired, name="synced", source="git", git_url="https://g.example/z.git",
                        auto_sync=True)
    await _add(db_session_factory, active, retired, synced, manual, editor, on_retired)

    assert await tasks._poll_git_stacks() == 1
    assert [(name, args) for name, args, _ in celery_calls] == [
        ("app.tasks.docker_jobs.sync_git_stack", (str(synced.id),))
    ]


# --- Scans -----------------------------------------------------------------------------------


async def test_a_scope_scan_with_nothing_to_scan_is_skipped(
    db_session_factory: Any, machine_shell: FakeMachine
) -> None:
    machine = _machine()
    job = _job(machine, DockerJobKind.IMAGE_SCAN, "scope:in_use", params={"scope": "in_use"})
    await _add(db_session_factory, machine, job)
    machine_shell.inventory = SimpleNamespace(
        images=[{"id": NEW_ID, "ref": "nginx:1.27", "in_use": False}], containers=[]
    )

    await tasks._run_docker_job(str(job.id))

    stored = await _get(db_session_factory, DockerJob, job.id)
    assert stored.status == DockerJobStatus.SKIPPED
    assert stored.result["note"] == "nothing_to_scan"
    assert machine_shell.started == []


async def test_a_scan_stores_results_and_summarizes_the_machine(
    db_session_factory: Any, machine_shell: FakeMachine
) -> None:
    machine = _machine()
    job = _job(machine, DockerJobKind.IMAGE_SCAN, "nginx:1.27",
               params={"images": {"nginx:1.27": NEW_ID}})
    await _add(db_session_factory, machine, job)
    machine_shell.inventory = SimpleNamespace(
        images=[{"id": NEW_ID}], containers=[{"image_id": NEW_ID}]
    )
    machine_shell.finishes(_scan_lines("nginx:1.27", ["CVE-1:CRITICAL", "CVE-2:HIGH"]))

    await tasks._run_docker_job(str(job.id))

    stored = await _get(db_session_factory, DockerJob, job.id)
    refreshed = await _get(db_session_factory, Machine, machine.id)
    assert stored.status == DockerJobStatus.SUCCEEDED
    assert (stored.result["scanned"], stored.result["failed"]) == (1, 0)
    assert refreshed.docker_vulnerabilities["critical"] == 1
    assert refreshed.docker_vulnerabilities["high"] == 1
    # The thousands of finding lines are kept with the scan, not in the job's log.
    assert "CVE-1" not in (stored.output or "")


async def test_a_scan_of_references_resolves_them_to_image_ids_on_the_machine(
    db_session_factory: Any, machine_shell: FakeMachine
) -> None:
    machine = _machine()
    job = _job(machine, DockerJobKind.IMAGE_SCAN, "2 images",
               params={"refs": ["nginx:1.27", "redis:7"]})
    await _add(db_session_factory, machine, job)
    machine_shell.inventory = SimpleNamespace(
        images=[
            {"id": NEW_ID, "ref": "nginx:1.27", "in_use": True},
            {"id": "sha256:" + "c" * 64, "ref": "postgres:17", "in_use": True},
        ],
        # redis:7 was re-tagged since: only its container still names it.
        containers=[{"image": "redis:7", "image_id": OLD_ID}],
    )
    machine_shell.finishes(
        _scan_lines("nginx:1.27", ["CVE-1:HIGH"]) + "\n" + _scan_lines("redis:7", [])
    )

    await tasks._run_docker_job(str(job.id))

    stored = await _get(db_session_factory, DockerJob, job.id)
    assert stored.result["images"] == {"nginx:1.27": NEW_ID, "redis:7": OLD_ID}
    assert stored.status == DockerJobStatus.SUCCEEDED
    [(_remote, script)] = machine_shell.started
    assert "postgres" not in script


async def test_a_scan_where_no_image_could_be_scanned_fails(
    db_session_factory: Any, machine_shell: FakeMachine
) -> None:
    machine = _machine()
    job = _job(machine, DockerJobKind.IMAGE_SCAN, "nginx:1.27",
               params={"images": {"nginx:1.27": NEW_ID}})
    await _add(db_session_factory, machine, job)
    machine_shell.finishes(_scan_lines("nginx:1.27", [], failed=True))

    await tasks._run_docker_job(str(job.id))

    stored = await _get(db_session_factory, DockerJob, job.id)
    assert stored.status == DockerJobStatus.FAILED
    assert stored.result["failed"] == 1


# --- Reads ---------------------------------------------------------------------------------


async def test_reads_report_missing_docker_access_as_such(
    db_session_factory: Any, machine_shell: FakeMachine
) -> None:
    machine = _machine()
    await _add(db_session_factory, machine)

    result = await tasks._docker_inventory(str(machine.id), ["containers"])

    assert result["ok"] is False and result["no_access"] is True


def _own_machine(own_host: set[uuid.UUID]) -> Machine:
    machine = _machine(
        docker_containers=[
            {"name": "debcontrol-web-1", "compose_project": "debcontrol", "state": "running"}
        ]
    )
    own_host.add(machine.id)
    return machine


async def test_a_queued_deploy_of_debcontrols_own_project_fails_when_it_runs(
    db_session_factory: Any, machine_shell: FakeMachine, own_host: set[uuid.UUID]
) -> None:
    # Queued before the machine was known to be debcontrol's own host.
    machine = _own_machine(own_host)
    stack = _stack(machine, name="debcontrol")
    job = _job(machine, DockerJobKind.STACK_DEPLOY, "debcontrol", ref_id=stack.id)
    await _add(db_session_factory, machine, stack, job)

    await tasks._run_docker_job(str(job.id))

    stored = await _get(db_session_factory, DockerJob, job.id)
    assert (stored.status, stored.error) == (DockerJobStatus.FAILED, PROTECTED_MESSAGE)
    assert machine_shell.started == []


async def test_a_queued_update_of_debcontrols_own_container_fails_when_it_runs(
    db_session_factory: Any, machine_shell: FakeMachine, own_host: set[uuid.UUID]
) -> None:
    machine = _own_machine(own_host)
    job = _job(machine, DockerJobKind.CONTAINER_UPDATE, "debcontrol-web-1", params={"gate": "off"})
    await _add(db_session_factory, machine, job)

    await tasks._run_docker_job(str(job.id))

    stored = await _get(db_session_factory, DockerJob, job.id)
    assert (stored.status, stored.error) == (DockerJobStatus.FAILED, PROTECTED_MESSAGE)
    assert machine_shell.started == []


async def test_git_sync_never_deploys_debcontrols_own_project(
    db_session_factory: Any,
    machine_shell: FakeMachine,
    own_host: set[uuid.UUID],
    celery_calls: RecordedCeleryCalls,
) -> None:
    machine = _own_machine(own_host)
    stack = _stack(
        machine,
        name="debcontrol",
        source="git",
        compose_content=None,
        git_url="https://git.example.com/me/debcontrol.git",
        git_branch="main",
        git_compose_path="compose.yaml",
    )
    await _add(db_session_factory, machine, stack)
    machine_shell.answer("", f"@@DC_COMMIT {NEW_COMMIT}\n")

    result = await tasks._sync_git_stack(str(stack.id), started_by="Git auto-sync")

    assert result == {"ok": False, "error": PROTECTED_MESSAGE}
    async with db_session_factory() as db:
        assert (await db.execute(select(DockerJob))).scalars().all() == []
    assert RUN_JOB not in celery_calls.names


async def test_writing_a_compose_file_sends_it_on_standard_input(
    db_session_factory: Any, machine_shell: FakeMachine, monkeypatch: pytest.MonkeyPatch
) -> None:
    machine = _machine()
    await _add(db_session_factory, machine)
    sent: list[Any] = []

    async def fake_run_script(
        _machine: Any, _secret: Any, _timeout: int, script: str, **kwargs: Any
    ) -> CommandOutput:
        sent.append((script, kwargs.get("stdin")))
        return CommandOutput(0, "@@DC_DONE\n")

    monkeypatch.setattr(tasks, "run_script", fake_run_script)
    files = ["/srv/app/compose.yaml"]

    ok = await tasks._docker_write_compose_file(
        str(machine.id), "app", files[0], "services: {}\n", "/srv/app", files
    )

    assert ok == {"ok": True}
    [(script, stdin)] = sent
    assert stdin == "services: {}\n"
    assert "services: {}" not in script

    async def failing(*_args: Any, **_kwargs: Any) -> CommandOutput:
        return CommandOutput(1, "yaml: bad\n@@DC_FAILED config\n")

    monkeypatch.setattr(tasks, "run_script", failing)
    failed = await tasks._docker_write_compose_file(
        str(machine.id), "app", files[0], "x", "/srv/app", files
    )
    assert failed == {"ok": False, "step": "config", "error": "yaml: bad"}
    refused = await tasks._docker_write_compose_file(
        str(machine.id), "app", "/etc/passwd", "x", "/srv/app", files
    )
    assert refused["ok"] is False
