"""The month calendar (`app.services.month_calendar`): scheduled runs,
maintenance windows and update batches, day by day."""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime
from typing import Any

from httpx2 import AsyncClient

from app.db.models.machine_update_run import MachineUpdateRun, UpdateRunStatus, UpgradeStrategy
from app.db.models.maintenance_window import MaintenanceWindow
from app.db.models.scheduled_task import ScheduledTask, ScheduleTargetType
from app.services import month_calendar
from tests.test_homelab_round import _add_machine
from tests.test_update_history import _api_token


def test_month_parameter_falls_back_to_this_month() -> None:
    today = date(2026, 10, 12)

    assert month_calendar.parse_month("2026-03", today) == (2026, 3)
    for bad in ("", "2026-13", "1999-01", "2026-3", "abcd-ef", "2026-03-01"):
        assert month_calendar.parse_month(bad, today) == (2026, 10), bad


def test_a_tasks_runs_are_those_of_its_cron_in_its_zone() -> None:
    task = ScheduledTask(cron_expression="30 3 * * 1", timezone="Europe/Prague")
    start, end = datetime(2026, 3, 1, tzinfo=UTC), datetime(2026, 4, 1, tzinfo=UTC)

    runs = month_calendar.task_runs(task, start, end)

    # Mondays 03:30 Prague: 02:30 UTC in winter, 01:30 UTC after the change.
    assert [r.day for r in runs] == [2, 9, 16, 23, 30]
    assert [r.hour for r in runs] == [2, 2, 2, 2, 1]
    assert month_calendar.task_runs(ScheduledTask(cron_expression="nonsense"), start, end) == []


async def _seed(db_session_factory: Any) -> uuid.UUID:
    first = await _add_machine(db_session_factory, name="m1", ip_address="10.0.5.1")
    second = await _add_machine(db_session_factory, name="m2", ip_address="10.0.5.2")
    batch_id = uuid.uuid4()
    async with db_session_factory() as db:
        db.add_all(
            [
                ScheduledTask(
                    name="Nightly updates",
                    action="system_update",
                    target_type=ScheduleTargetType.ALL_MACHINES,
                    cron_expression="0 3 * * *",
                ),
                ScheduledTask(
                    name="Sampling",
                    action="force_monitoring_sample",
                    target_type=ScheduleTargetType.ALL_MACHINES,
                    cron_expression="*/15 * * * *",
                    is_enabled=False,
                ),
                MaintenanceWindow(
                    name="Rack move",
                    starts_at=datetime(2026, 3, 10, 20, 0, tzinfo=UTC),
                    ends_at=datetime(2026, 3, 12, 6, 0, tzinfo=UTC),
                    all_machines=True,
                    pause_scheduled_tasks=True,
                ),
            ]
        )
        for machine_id, status in (
            (first, UpdateRunStatus.SUCCEEDED),
            (second, UpdateRunStatus.FAILED),
        ):
            db.add(
                MachineUpdateRun(
                    machine_id=machine_id,
                    strategy=UpgradeStrategy.UPGRADE,
                    status=status,
                    batch_id=batch_id,
                    created_at=datetime(2026, 3, 5, 3, 0, 5, tzinfo=UTC),
                )
            )
        await db.commit()
    return batch_id


async def test_calendar_page_and_api(client: AsyncClient, db_session_factory: Any) -> None:
    batch_id = await _seed(db_session_factory)
    headers = await _api_token(client)

    page = await client.get("/scheduling/calendar?month=2026-03")
    listing = await client.get("/scheduling")
    api = (
        await client.get("/api/v1/scheduling/calendar?month=2026-03", headers=headers)
    ).json()

    assert page.status_code == 200
    assert "Calendar: March 2026" in page.text
    assert 'href="/scheduling/calendar?month=2026-02"' in page.text
    assert 'href="/scheduling/calendar?month=2026-04"' in page.text
    assert f'href="/machine-groups/batches/{batch_id}"' in page.text
    assert "Update of 2 machines · 1 failed" in page.text
    assert "Sampling" in page.text and "96 (off)" in page.text
    assert 'href="/scheduling/calendar"' in listing.text

    days = {day["date"]: day["entries"] for day in api["days"]}
    assert api["month"] == "2026-03" and len(days) == 31
    fifth = days["2026-03-05"]
    assert [e["kind"] for e in fifth].count("task") == 2
    batch = next(e for e in fifth if e["kind"] == "batch")
    assert (batch["label"], batch["count"], batch["flag"]) == ("2", 1, True)
    # The window covers three days; only its first carries the start time.
    windows = {d: [e for e in days[d] if e["kind"] == "window"] for d in days}
    assert [d for d, found in windows.items() if found] == [
        "2026-03-10",
        "2026-03-11",
        "2026-03-12",
    ]
    assert windows["2026-03-10"][0]["at"] is not None and windows["2026-03-11"][0]["at"] is None
    assert windows["2026-03-10"][0]["flag"] is True
