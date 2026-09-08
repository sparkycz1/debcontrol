"""Coverage for the scheduled-task run history: `_run_scheduled_task`
writing a `ScheduledTaskRun` row on every firing, and the web/API routes
that read it back. Real SSH/Celery dispatch stays mocked out via the
autouse `celery_calls` fixture — `check_updates` against an empty target
list needs neither.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select

from app.db.models.role import Permission
from app.db.models.scheduled_task import ScheduledTask, ScheduleTargetType
from app.db.models.scheduled_task_run import ScheduledTaskRun, ScheduledTaskRunStatus
from app.scheduling.jobs import _run_scheduled_task


async def _make_task(db_session_factory: Any, **overrides: Any) -> uuid.UUID:
    async with db_session_factory() as session:
        task = ScheduledTask(
            name=overrides.get("name", "Nightly check"),
            action=overrides.get("action", "check_updates"),
            target_type=overrides.get("target_type", ScheduleTargetType.ALL_MACHINES),
            cron_expression="0 3 * * *",
            is_enabled=True,
        )
        session.add(task)
        await session.commit()
        await session.refresh(task)
        return task.id


async def test_run_scheduled_task_records_a_history_row(
    db_session_factory, celery_calls, monkeypatch
):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    task_id = await _make_task(db_session_factory)

    result = await _run_scheduled_task(str(task_id))

    assert result["ok"] is True
    async with db_session_factory() as session:
        runs = (
            await session.execute(
                select(ScheduledTaskRun).where(ScheduledTaskRun.scheduled_task_id == task_id)
            )
        ).scalars().all()
        assert len(runs) == 1
        run = runs[0]
        assert run.status == ScheduledTaskRunStatus.SUCCEEDED
        assert run.action == "check_updates"
        assert run.attempted == 0  # no machines exist in this test
        assert run.started_at <= run.finished_at


async def test_run_scheduled_task_records_a_failed_row_for_an_unknown_action(
    db_session_factory, celery_calls, monkeypatch
):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    task_id = await _make_task(db_session_factory, action="not_a_real_action")

    result = await _run_scheduled_task(str(task_id))

    assert result["ok"] is False
    async with db_session_factory() as session:
        run = (
            await session.execute(
                select(ScheduledTaskRun).where(ScheduledTaskRun.scheduled_task_id == task_id)
            )
        ).scalar_one()
        assert run.status == ScheduledTaskRunStatus.FAILED
        assert "not_a_real_action" in run.summary


async def test_scheduling_history_page_lists_runs(
    client, db_session_factory, celery_calls, monkeypatch
):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    task_id = await _make_task(db_session_factory)
    await _run_scheduled_task(str(task_id))

    response = await client.get(f"/scheduling/{task_id}/history")

    assert response.status_code == 200
    assert "check_updates" in response.text


async def test_scheduling_history_page_empty_state(client, db_session_factory):
    task_id = await _make_task(db_session_factory)

    response = await client.get(f"/scheduling/{task_id}/history")

    assert response.status_code == 200
    assert "hasn&#39;t fired yet" in response.text or "hasn't fired yet" in response.text


async def test_scheduling_history_requires_scheduling_view_permission(
    client, login_as, db_session_factory
):
    task_id = await _make_task(db_session_factory)
    await login_as(client, permissions={Permission.MACHINE_VIEW})

    response = await client.get(f"/scheduling/{task_id}/history")

    assert response.status_code == 403


async def test_scheduling_history_404s_for_an_unknown_task(client):
    response = await client.get(f"/scheduling/{uuid.uuid4()}/history")

    assert response.status_code == 404
