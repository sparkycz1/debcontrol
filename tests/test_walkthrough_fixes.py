"""Small fixes from a walk through a live instance: update runs abandoned
by a stopped worker are closed, run states are translated, look-ups stay
off the History tab, and a firmware pseudo-filesystem is not a disk."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from httpx2 import AsyncClient
from sqlalchemy import select

from app.db.models.audit_log import AuditLogEntry
from app.db.models.machine import Machine
from app.db.models.machine_update_run import MachineUpdateRun, UpdateRunStatus, UpgradeStrategy
from app.services import machine_timeline
from app.ssh import facts, monitoring
from app.tasks import jobs
from tests.test_homelab_round import _add_machine


async def _run(
    db_session_factory: Any,
    machine_id: uuid.UUID,
    *,
    started_hours_ago: float,
    status: UpdateRunStatus = UpdateRunStatus.RUNNING,
    rollout_position: int | None = None,
) -> uuid.UUID:
    async with db_session_factory() as db:
        run = MachineUpdateRun(
            machine_id=machine_id,
            strategy=UpgradeStrategy.FULL_UPGRADE,
            status=status,
            started_at=datetime.now(UTC) - timedelta(hours=started_hours_ago),
            rollout_position=rollout_position,
            batch_id=uuid.uuid4(),
        )
        db.add(run)
        await db.commit()
        return run.id


async def test_abandoned_runs_are_closed_and_fresh_ones_left_alone(
    db_session_factory: Any, monkeypatch: Any
) -> None:
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    machine_id = await _add_machine(db_session_factory)
    stale = await _run(db_session_factory, machine_id, started_hours_ago=30)
    rolling = await _run(db_session_factory, machine_id, started_hours_ago=30, rollout_position=0)
    fresh = await _run(db_session_factory, machine_id, started_hours_ago=0.1)
    done = await _run(
        db_session_factory, machine_id, started_hours_ago=30, status=UpdateRunStatus.SUCCEEDED
    )
    released: list[str] = []
    monkeypatch.setattr(jobs.finish_update_run, "delay", lambda run_id: released.append(run_id))

    closed = await jobs._fail_stale_update_runs()
    again = await jobs._fail_stale_update_runs()

    async with db_session_factory() as db:
        runs = {r.id: r for r in (await db.execute(select(MachineUpdateRun))).scalars().all()}
        actions = list((await db.execute(select(AuditLogEntry.action))).scalars().all())
    assert (closed, again) == (2, 0)
    for run_id in (stale, rolling):
        assert runs[run_id].status == UpdateRunStatus.FAILED
        assert runs[run_id].error == jobs.STALE_RUN_ERROR
        assert runs[run_id].finished_at is not None
    assert runs[fresh].status == UpdateRunStatus.RUNNING
    assert runs[done].status == UpdateRunStatus.SUCCEEDED
    # Only the rolling batch has anything waiting on it.
    assert released == [str(rolling)]
    assert actions.count("machine_update_runs.reap") == 1


async def test_run_states_are_translated_in_the_history(
    client: AsyncClient, db_session_factory: Any
) -> None:
    machine_id = await _add_machine(db_session_factory)
    await _run(db_session_factory, machine_id, started_hours_ago=0.1)
    await client.get("/account")
    await client.post(
        "/account/locale", data={"csrf_token": client.cookies.get("csrftoken"), "locale": "cs"}
    )

    page = await client.get(f"/machines/{machine_id}/updates")
    listing = await client.get("/machines")

    assert '<span class="badge badge-warn">běží</span>' in page.text
    assert ">running<" not in page.text and ">pending<" not in page.text
    assert "čeká" in page.text and "selhalo" in page.text
    assert "mašiny" not in listing.text


async def test_history_leaves_out_browsing_and_the_duplicate_of_a_run(
    db_session_factory: Any,
) -> None:
    machine_id = await _add_machine(db_session_factory)
    async with db_session_factory() as db:
        for action in ("machine.logs.browse", "machine.updates.run", "machine.power.reboot"):
            db.add(
                AuditLogEntry(
                    actor="alice",
                    action=action,
                    summary=action,
                    target_type="machine",
                    target_id=str(machine_id),
                )
            )
        await db.commit()
        machine = await db.get(Machine, machine_id)
        assert machine is not None

        timeline = await machine_timeline.load_timeline(
            db, machine, days=1, include_audit=True, kinds={"audit"}
        )

    assert [event.data["action"] for event in timeline.events] == ["machine.power.reboot"]


def test_efi_variables_are_not_listed_as_a_filesystem() -> None:
    assert "-x efivarfs" in monitoring.MONITORING_COMMAND
    assert "-x efivarfs" in facts.FACTS_COMMAND
