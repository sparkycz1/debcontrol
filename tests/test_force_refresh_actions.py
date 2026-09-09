"""`trigger_facts_refresh`/`trigger_monitoring_sample`
(`app.services.machine_actions`) — the fleet-wide "force a sweep now"
debug actions Scheduling exposes as `force_facts_refresh`/
`force_monitoring_sample`. Real SSH/Celery dispatch stays mocked out via
the autouse `celery_calls` fixture.
"""

from __future__ import annotations

from typing import Any

from app.db.models.machine import AuthMethod, Machine
from app.services.machine_actions import trigger_facts_refresh, trigger_monitoring_sample


async def _make_machine(db_session_factory: Any, *, pinned: bool = True) -> Machine:
    async with db_session_factory() as db:
        machine = Machine(
            name="force-refresh-target",
            ip_address="10.1.2.3",
            port=22,
            username="admin",
            auth_method=AuthMethod.SSH_KEY,
            host_key_fingerprint="SHA256:fakefingerprint" if pinned else None,
        )
        db.add(machine)
        await db.commit()
        await db.refresh(machine)
        return machine


async def test_trigger_facts_refresh_enqueues_all_four_tasks(db_session_factory, celery_calls):
    machine = await _make_machine(db_session_factory)

    skipped = await trigger_facts_refresh([machine])

    assert skipped == 0
    assert celery_calls.names == [
        "app.tasks.jobs.refresh_machine_facts",
        "app.tasks.jobs.refresh_machine_packages",
        "app.tasks.jobs.refresh_machine_services",
        "app.tasks.jobs.check_machine_readiness",
    ]
    assert all(call[1] == (str(machine.id),) for call in celery_calls)


async def test_trigger_facts_refresh_skips_unpinned_machines(db_session_factory, celery_calls):
    machine = await _make_machine(db_session_factory, pinned=False)

    skipped = await trigger_facts_refresh([machine])

    assert skipped == 1
    assert celery_calls.names == []


async def test_trigger_monitoring_sample_enqueues_the_sample_task(
    db_session_factory, celery_calls
):
    machine = await _make_machine(db_session_factory)

    skipped = await trigger_monitoring_sample([machine])

    assert skipped == 0
    assert celery_calls.names == ["app.tasks.jobs.sample_machine_monitoring"]
    assert celery_calls[0][1] == (str(machine.id),)
