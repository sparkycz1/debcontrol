"""`MachineUpdateRun` retention/purge — see app/db/models/app_settings.py's
docstring on `machine_update_run_retention_days` for why this exists (no
purge at all previously meant this table grew forever on a fleet running
recurring scheduled updates). Same shape as the dashboard-trends retention
tests (tests/test_dashboard_trends.py) — this table was following it.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.app_settings import get_or_create_app_settings
from app.db.models.machine import AuthMethod, Machine
from app.db.models.machine_update_run import MachineUpdateRun, UpdateRunStatus, UpgradeStrategy

# The async implementation behind the Celery task of the same (unprefixed)
# name — the task itself is a thin `asyncio.run(...)` wrapper, and calling
# that from inside a running event loop is not possible.
from app.tasks.jobs import _purge_old_machine_update_runs


async def _make_run(db: AsyncSession, machine_id: uuid.UUID, *, created_at: datetime) -> None:
    db.add(
        MachineUpdateRun(
            machine_id=machine_id,
            strategy=UpgradeStrategy.DIST_UPGRADE,
            status=UpdateRunStatus.SUCCEEDED,
            output="ok",
            created_at=created_at,
        )
    )


async def test_purge_old_machine_update_runs_respects_retention(db_session_factory, monkeypatch):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    async with db_session_factory() as db:
        app_settings = await get_or_create_app_settings(db)
        app_settings.machine_update_run_retention_days = 30

        machine = Machine(
            name="m1", ip_address="10.1.1.1", username="admin", auth_method=AuthMethod.SSH_KEY
        )
        db.add(machine)
        await db.flush()

        old_at = datetime.now(UTC) - timedelta(days=60)
        recent_at = datetime.now(UTC) - timedelta(days=1)
        await _make_run(db, machine.id, created_at=old_at)
        await _make_run(db, machine.id, created_at=recent_at)
        await db.commit()

    await _purge_old_machine_update_runs()

    async with db_session_factory() as db:
        result = await db.execute(select(MachineUpdateRun))
        remaining = list(result.scalars().all())
        assert len(remaining) == 1
        assert remaining[0].created_at.replace(tzinfo=UTC) - recent_at < timedelta(seconds=5)


async def test_purge_old_machine_update_runs_skipped_when_retention_unset(
    db_session_factory, monkeypatch
):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    async with db_session_factory() as db:
        app_settings = await get_or_create_app_settings(db)
        app_settings.machine_update_run_retention_days = None

        machine = Machine(
            name="m1", ip_address="10.1.1.1", username="admin", auth_method=AuthMethod.SSH_KEY
        )
        db.add(machine)
        await db.flush()
        await _make_run(db, machine.id, created_at=datetime.now(UTC) - timedelta(days=9999))
        await db.commit()

    await _purge_old_machine_update_runs()

    async with db_session_factory() as db:
        result = await db.execute(select(MachineUpdateRun))
        assert len(list(result.scalars().all())) == 1


async def test_update_run_retention_setting_persists_and_redirects_to_security_tab(client):
    await client.get("/settings")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/settings/update-run-retention",
        data={"retention_days": "45", "csrf_token": csrf_token},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/settings?tab=security"

    page = await client.get("/settings?tab=security")
    assert 'value="45"' in page.text


async def test_update_run_retention_rejects_negative(client):
    await client.get("/settings")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/settings/update-run-retention",
        data={"retention_days": "-1", "csrf_token": csrf_token},
    )
    assert response.status_code == 200
    assert "isn&#39;t a whole number" in response.text or "isn't a whole number" in response.text
