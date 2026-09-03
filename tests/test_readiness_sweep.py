"""The periodic readiness sweep (`app.tasks.jobs._refresh_all_machine_readiness`)
— added because `check_machine_readiness` used to only ever run on-demand
(right after a host key was first trusted, or an explicit "Re-check"
click), so a requirement that got un-set later (ncurses-term removed by
`autoremove`, a sudoers grant edited away) never surfaced on its own. See
app/tasks/jobs.py and app/tasks/celery_app.py's beat_schedule.
"""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.tasks.jobs as jobs
from app.db.models.machine import AuthMethod, Machine
from app.tasks.celery_app import celery_app
from tests.test_onboarding import _make_machine


async def test_readiness_sweep_enqueues_only_machines_with_a_pinned_host_key(
    db_session_factory: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    ready_id = await _make_machine(db_session_factory)  # has a pinned host key

    async with db_session_factory() as session:
        no_key_machine = Machine(
            name="no-host-key-yet",
            ip_address="10.9.9.10",
            port=22,
            username="root",
            auth_method=AuthMethod.PASSWORD,
            secret_encrypted=None,
            host_key_fingerprint=None,
        )
        inactive_machine = Machine(
            name="deactivated",
            ip_address="10.9.9.11",
            port=22,
            username="root",
            auth_method=AuthMethod.PASSWORD,
            secret_encrypted=None,
            host_key_fingerprint="SHA256:fakefingerprint",
            is_active=False,
        )
        session.add_all([no_key_machine, inactive_machine])
        await session.commit()

    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)

    enqueued: list[str] = []
    monkeypatch.setattr(
        jobs.check_machine_readiness, "delay", lambda machine_id: enqueued.append(machine_id)
    )

    await jobs._refresh_all_machine_readiness()

    assert enqueued == [str(ready_id)]


async def test_readiness_sweep_is_registered_on_the_facts_refresh_cadence():
    entry = celery_app.conf.beat_schedule["refresh-all-machine-readiness"]

    assert entry["task"] == "app.tasks.jobs.refresh_all_machine_readiness"
    # Same interval object the facts/packages/services sweeps use — see
    # celery_app.py's beat_schedule.
    facts_entry = celery_app.conf.beat_schedule["refresh-all-machine-facts"]
    assert entry["schedule"] == facts_entry["schedule"]
