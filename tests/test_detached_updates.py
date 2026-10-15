"""Update runs survive debcontrol stopping in the middle: the update runs
detached on the machine (`app.ssh.detached_updates`), a run whose task went
away is resumed and reads how its job ended, and runs lost from the queue
are queued again after a restart (`app.tasks.jobs._reconcile_update_runs`).

The shell side is exercised for real, with a local `sh` standing in for
the SSH connection and a short script standing in for apt."""

from __future__ import annotations

import asyncio
import contextlib
import os
import subprocess
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select

from app.db.models.audit_log import AuditLogEntry
from app.db.models.machine_update_run import MachineUpdateRun, UpdateRunStatus, UpgradeStrategy
from app.ssh import detached_updates
from app.ssh.exceptions import SSHConnectionError
from app.tasks import jobs
from tests.conftest import RecordedCeleryCalls
from tests.test_homelab_round import _add_machine


class _Completed:
    def __init__(self, stdout: Any, exit_status: int) -> None:
        self.stdout = stdout
        self.stderr = ""
        self.exit_status = exit_status


class _LocalConnection:
    """Runs each command with the local `sh`, `HOME` pointing at `home`."""

    def __init__(self, home: Path) -> None:
        self.home = home

    async def run(self, command: str, **kwargs: Any) -> _Completed:
        env = {**os.environ, "HOME": str(self.home)}
        done = await asyncio.to_thread(
            subprocess.run, ["sh", "-c", command], capture_output=True, env=env, timeout=30
        )
        if kwargs.get("encoding", "utf-8") is None:
            return _Completed(done.stdout, done.returncode)
        return _Completed(done.stdout.decode(), done.returncode)

    async def __aenter__(self) -> _LocalConnection:
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False


@pytest.fixture
def local_machine(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Point the detached-update SSH calls at the local shell, and make the
    "update" a short script: prints two lines, exits with $DC_TEST_EXIT."""

    async def fake_open(*_args: Any, **_kwargs: Any) -> _LocalConnection:
        return _LocalConnection(tmp_path)

    monkeypatch.setattr(detached_updates, "open_connection", fake_open)
    monkeypatch.setattr(
        detached_updates,
        "build_update_command",
        lambda _strategy: 'echo "Reading package lists..."; sleep 0.3; echo "0 upgraded."; '
        'exit "${DC_TEST_EXIT:-0}"',
    )
    return tmp_path


def _job_dir(home: Path) -> Path:
    return home / ".local" / "state" / "debcontrol" / "updates"


async def test_a_job_runs_on_its_own_and_starts_only_once(local_machine: Path) -> None:
    job = str(uuid.uuid4())
    machine: Any = object()

    first = await detached_updates.start(machine, None, job, UpgradeStrategy.FULL_UPGRADE, 5)
    again = await detached_updates.start(machine, None, job, UpgradeStrategy.FULL_UPGRADE, 5)
    seen: list[str] = []

    async def on_output(text: str) -> None:
        seen.append(text)

    result = await detached_updates.follow(
        machine, None, job, 5, 30, on_output=on_output, poll_seconds=0.1
    )

    assert (first, again) == (True, False)
    assert result.state == "finished"
    assert result.exit_status == 0
    assert result.output == "Reading package lists...\n0 upgraded.\n"
    assert seen[-1] == result.output
    # Read, then cleaned up.
    assert list(_job_dir(local_machine).iterdir()) == []


async def test_the_exit_status_and_a_finished_job_are_read_later(
    local_machine: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DC_TEST_EXIT", "100")
    job = str(uuid.uuid4())
    machine: Any = object()
    await detached_updates.start(machine, None, job, UpgradeStrategy.UPGRADE, 5)
    await asyncio.sleep(1.0)  # nobody watching while it ends

    # No time left at all: still one look.
    result = await detached_updates.follow(machine, None, job, 5, 0)

    assert (result.state, result.exit_status) == ("finished", 100)
    assert "0 upgraded." in result.output


async def test_a_job_that_died_reads_as_lost_and_an_unknown_one_as_missing(
    local_machine: Path,
) -> None:
    job = str(uuid.uuid4())
    machine: Any = object()
    await detached_updates.start(machine, None, job, UpgradeStrategy.UPGRADE, 5)
    pid = int((_job_dir(local_machine) / f"{job}.pid").read_text())
    os.kill(pid, 9)
    await asyncio.sleep(0.3)

    lost = await detached_updates.follow(machine, None, job, 5, 5, poll_seconds=0.1)
    missing = await detached_updates.follow(machine, None, str(uuid.uuid4()), 5, 0)

    assert lost.state == "lost"
    assert missing.state == "missing"


async def test_a_dropped_connection_is_reconnected(
    local_machine: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    job = str(uuid.uuid4())
    machine: Any = object()
    await detached_updates.start(machine, None, job, UpgradeStrategy.UPGRADE, 5)
    attempts = 0

    async def flaky(*_args: Any, **_kwargs: Any) -> _LocalConnection:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise SSHConnectionError("connection refused")
        return _LocalConnection(local_machine)

    monkeypatch.setattr(detached_updates, "open_connection", flaky)

    result = await detached_updates.follow(
        machine, None, job, 5, 30, poll_seconds=0.1, reconnect_seconds=0.05
    )

    assert result.state == "finished"
    assert attempts == 3


def test_job_ids_are_never_put_in_a_command_unchecked() -> None:
    with pytest.raises(ValueError):
        detached_updates.build_poll_command("x; reboot", 0)


def test_checking_a_machine_reads_dpkg_and_what_is_left() -> None:
    clean = detached_updates.parse_verify_output(
        "===DC_DPKG_AUDIT===\n===DC_UPGRADE_SIM===\nReading package lists...\n", 0
    )
    pending = detached_updates.parse_verify_output(
        "===DC_DPKG_AUDIT===\n===DC_UPGRADE_SIM===\nInst a [1] (2 x)\nInst b [1] (2 x)\n", 0
    )
    broken = detached_updates.parse_verify_output(
        "===DC_DPKG_AUDIT===\nThe following packages are only half configured\n"
        "===DC_UPGRADE_SIM===\n",
        0,
    )

    assert (clean.ok, pending.ok, broken.ok) == (True, False, False)
    assert pending.detail == "2 packages still to upgrade."
    assert "half-installed" in broken.detail


# --- The update run task ------------------------------------------------------


async def _make_run(db_session_factory: Any, **fields: Any) -> uuid.UUID:
    machine_id = fields.pop("machine_id", None) or await _add_machine(db_session_factory)
    async with db_session_factory() as db:
        run = MachineUpdateRun(
            machine_id=machine_id, strategy=UpgradeStrategy.FULL_UPGRADE, **fields
        )
        db.add(run)
        await db.commit()
        return run.id


async def _get(db_session_factory: Any, run_id: uuid.UUID) -> MachineUpdateRun:
    async with db_session_factory() as db:
        run: MachineUpdateRun | None = await db.get(MachineUpdateRun, run_id)
        assert run is not None
        return run


@pytest.fixture
def no_package_snapshot(monkeypatch: pytest.MonkeyPatch, db_session_factory: Any) -> None:
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)

    async def fake_packages(*_args: Any, **_kwargs: Any) -> dict[str, str]:
        return {"apt": "2.6"}

    monkeypatch.setattr(jobs, "capture_package_snapshot", fake_packages)


async def test_a_run_is_started_detached_followed_and_recorded(
    db_session_factory: Any,
    local_machine: Path,
    no_package_snapshot: None,
    celery_calls: RecordedCeleryCalls,
) -> None:
    run_id = await _make_run(db_session_factory, batch_id=uuid.uuid4())

    await jobs._run_machine_update(str(run_id))
    # Queued twice (a restart re-queues what was pending): runs once.
    await jobs._run_machine_update(str(run_id))

    run = await _get(db_session_factory, run_id)
    assert run.status == UpdateRunStatus.SUCCEEDED
    assert run.remote_job == str(run_id)
    assert run.output == "Reading package lists...\n0 upgraded.\n"
    assert run.package_snapshot == '{"apt": "2.6"}'
    assert celery_calls.names.count("app.tasks.jobs.release_held_runs") == 1


async def test_a_run_whose_task_stopped_reads_its_result_when_resumed(
    db_session_factory: Any,
    local_machine: Path,
    no_package_snapshot: None,
    monkeypatch: pytest.MonkeyPatch,
    celery_calls: RecordedCeleryCalls,
) -> None:
    monkeypatch.setenv("DC_TEST_EXIT", "100")
    long_ago = datetime.now(UTC) - timedelta(minutes=10)
    run_id = await _make_run(
        db_session_factory,
        status=UpdateRunStatus.RUNNING,
        started_at=long_ago,
        heartbeat_at=long_ago,
    )
    job = str(run_id)
    async with db_session_factory() as db:
        stored = await db.get(MachineUpdateRun, run_id)
        assert stored is not None
        stored.remote_job = job
        await db.commit()
    # The job ran on while debcontrol was away.
    await detached_updates.start(object(), None, job, UpgradeStrategy.FULL_UPGRADE, 5)  # type: ignore[arg-type]
    await asyncio.sleep(1.0)

    summary = await jobs._reconcile_update_runs()
    resume_calls = [c for c in celery_calls if c[0] == "app.tasks.jobs.resume_machine_update"]
    assert summary["resumed"] == 1
    assert len(resume_calls) == 1
    _name, args, _kwargs = resume_calls[0]
    # A resume task left behind by an earlier sweep does nothing.
    await jobs._resume_machine_update(str(run_id), long_ago.isoformat())
    assert (await _get(db_session_factory, run_id)).status == UpdateRunStatus.RUNNING
    await jobs._resume_machine_update(*args)

    run = await _get(db_session_factory, run_id)
    assert run.status == UpdateRunStatus.FAILED
    assert run.error == "apt exited with status 100."
    assert run.output is not None
    assert "[debcontrol] Reconnected after debcontrol restarted." in run.output
    assert "0 upgraded." in run.output


async def test_a_run_from_before_is_settled_by_checking_the_machine(
    db_session_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
    no_package_snapshot: None,
) -> None:
    started = datetime.now(UTC) - timedelta(hours=3)
    ok_run = await _make_run(db_session_factory, status=UpdateRunStatus.RUNNING, started_at=started)
    away_run = await _make_run(
        db_session_factory, status=UpdateRunStatus.RUNNING, started_at=datetime.now(UTC)
    )
    late_run = await _make_run(
        db_session_factory, status=UpdateRunStatus.RUNNING, started_at=started
    )
    reachable = {ok_run}
    current: list[uuid.UUID] = []

    async def fake_verify(*_args: Any, **_kwargs: Any) -> detached_updates.Verification:
        if current[-1] not in reachable:
            raise SSHConnectionError("no route to host")
        clean = "===DC_DPKG_AUDIT===\n===DC_UPGRADE_SIM===\n"
        return detached_updates.parse_verify_output(clean, 0)

    monkeypatch.setattr(detached_updates, "verify", fake_verify)
    for run_id in (ok_run, away_run, late_run):
        current.append(run_id)
        with contextlib.suppress(jobs._TryLaterError):
            await jobs._resume_machine_update(str(run_id))

    ok, away, late = [await _get(db_session_factory, r) for r in (ok_run, away_run, late_run)]
    assert ok.status == UpdateRunStatus.SUCCEEDED
    assert ok.output is not None and "Nothing left to upgrade" in ok.output
    # Unreachable, but still within the time an update may take: tried again later.
    assert away.status == UpdateRunStatus.RUNNING
    # Unreachable past it: closed.
    assert late.status == UpdateRunStatus.FAILED
    assert late.error is not None and late.error.startswith(jobs.STALE_RUN_ERROR)


async def test_after_a_restart_what_was_waiting_is_queued_again(
    db_session_factory: Any, monkeypatch: pytest.MonkeyPatch, celery_calls: RecordedCeleryCalls
) -> None:
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    machine_id = await _add_machine(db_session_factory)
    parallel = uuid.uuid4()
    rolling = uuid.uuid4()
    fresh = datetime.now(UTC)
    pending = await _make_run(db_session_factory, machine_id=machine_id, batch_id=parallel)
    await _make_run(
        db_session_factory,
        machine_id=machine_id,
        batch_id=parallel,
        status=UpdateRunStatus.RUNNING,
        started_at=fresh,
        heartbeat_at=fresh,
    )
    await _make_run(db_session_factory, machine_id=machine_id, batch_id=parallel, hold_order=1)
    done = await _make_run(
        db_session_factory,
        machine_id=machine_id,
        batch_id=rolling,
        rollout_position=0,
        status=UpdateRunStatus.SUCCEEDED,
    )
    await _make_run(db_session_factory, machine_id=machine_id, batch_id=rolling, rollout_position=1)
    await _make_run(db_session_factory, machine_id=machine_id, batch_id=rolling, rollout_position=2)

    quiet = await jobs._reconcile_update_runs()
    assert quiet == {"resumed": 0, "requeued": 0}
    assert celery_calls == []

    await jobs._reconcile_update_runs(after_restart=True)

    assert sorted((name.rsplit(".", 1)[1], args) for name, args, _ in celery_calls) == [
        ("finish_update_run", (str(done),)),
        ("release_held_runs", (str(parallel),)),
        ("run_machine_update", (str(pending),)),
    ]
    async with db_session_factory() as db:
        actions = list((await db.execute(select(AuditLogEntry.action))).scalars().all())
    assert actions == ["machine_update_runs.resume"]
