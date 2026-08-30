"""Dashboard trends (Task 4) — the daily `FleetSnapshot` job, its retention
setting/purge, the Dashboard's SVG trend chart(s), and the matching
read-only API endpoint.
"""

from __future__ import annotations

import re
from datetime import UTC, date, datetime, timedelta

from httpx import AsyncClient

from app.core.app_settings import get_or_create_app_settings
from app.db.models.fleet_snapshot import FleetSnapshot
from app.db.models.machine import AuthMethod, Machine

# The async implementations behind the Celery tasks of the same (unprefixed)
# names — the tasks themselves are thin `asyncio.run(...)` wrappers, and
# calling those from inside a running event loop is not possible.
from app.tasks.jobs import _purge_old_fleet_snapshots, _record_fleet_snapshot


async def _api_token(client: AsyncClient) -> dict[str, str]:
    await client.get("/account")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/account/api-tokens", data={"name": "trend-test", "csrf_token": csrf_token}
    )
    match = re.search(r"<textarea readonly rows=\"2\">([^<]+)</textarea>", response.text)
    assert match is not None
    return {"Authorization": f"Bearer {match.group(1)}"}


async def test_dashboard_hides_trend_chart_with_fewer_than_two_snapshots(client):
    response = await client.get("/dashboard")
    assert response.status_code == 200
    assert "Fleet trends" not in response.text


async def test_record_fleet_snapshot_creates_one_row_per_day(db_session_factory, monkeypatch):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    async with db_session_factory() as db:
        db.add(
            Machine(
                name="m1",
                ip_address="10.1.1.1",
                username="admin",
                auth_method=AuthMethod.SSH_KEY,
                is_reachable=True,
            )
        )
        await db.commit()

    await _record_fleet_snapshot()

    async with db_session_factory() as db:
        from sqlalchemy import select

        result = await db.execute(select(FleetSnapshot))
        snapshots = list(result.scalars().all())
        assert len(snapshots) == 1
        assert snapshots[0].total_machines == 1
        assert snapshots[0].online_machines == 1

    # Running it again the same day is a no-op (idempotent per calendar day).
    await _record_fleet_snapshot()
    async with db_session_factory() as db:
        from sqlalchemy import select

        result = await db.execute(select(FleetSnapshot))
        assert len(list(result.scalars().all())) == 1


async def test_dashboard_shows_trend_chart_with_two_or_more_snapshots(client, db_session_factory):
    async with db_session_factory() as db:
        db.add(
            FleetSnapshot(
                snapshot_date=date.today() - timedelta(days=1),
                total_machines=2,
                online_machines=1,
                offline_machines=1,
                needs_updates=1,
                needs_security_updates=0,
                needs_reboot=0,
            )
        )
        db.add(
            FleetSnapshot(
                snapshot_date=date.today(),
                total_machines=2,
                online_machines=2,
                offline_machines=0,
                needs_updates=0,
                needs_security_updates=0,
                needs_reboot=0,
            )
        )
        await db.commit()

    response = await client.get("/dashboard")
    assert response.status_code == 200
    assert "Fleet trends" in response.text
    assert "<svg" in response.text
    assert "<polyline" in response.text
    # No inline style attributes/blocks anywhere in the chart markup — this
    # app's CSP forbids both (style-src 'self', no 'unsafe-inline').
    assert "style=" not in response.text
    assert "<style" not in response.text


async def test_purge_old_fleet_snapshots_respects_retention(db_session_factory, monkeypatch):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    async with db_session_factory() as db:
        app_settings = await get_or_create_app_settings(db)
        app_settings.dashboard_trends_retention_days = 30
        await db.commit()

        old_date = (datetime.now(UTC) - timedelta(days=60)).date()
        recent_date = (datetime.now(UTC) - timedelta(days=1)).date()
        db.add(
            FleetSnapshot(
                snapshot_date=old_date,
                total_machines=1,
                online_machines=1,
                offline_machines=0,
                needs_updates=0,
                needs_security_updates=0,
                needs_reboot=0,
            )
        )
        db.add(
            FleetSnapshot(
                snapshot_date=recent_date,
                total_machines=1,
                online_machines=1,
                offline_machines=0,
                needs_updates=0,
                needs_security_updates=0,
                needs_reboot=0,
            )
        )
        await db.commit()

    await _purge_old_fleet_snapshots()

    async with db_session_factory() as db:
        from sqlalchemy import select

        result = await db.execute(select(FleetSnapshot))
        remaining = list(result.scalars().all())
        assert len(remaining) == 1
        assert remaining[0].snapshot_date == recent_date


async def test_purge_skipped_when_retention_unset(db_session_factory, monkeypatch):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    async with db_session_factory() as db:
        app_settings = await get_or_create_app_settings(db)
        app_settings.dashboard_trends_retention_days = None
        old_date = (datetime.now(UTC) - timedelta(days=9999)).date()
        db.add(
            FleetSnapshot(
                snapshot_date=old_date,
                total_machines=1,
                online_machines=1,
                offline_machines=0,
                needs_updates=0,
                needs_security_updates=0,
                needs_reboot=0,
            )
        )
        await db.commit()

    await _purge_old_fleet_snapshots()

    async with db_session_factory() as db:
        from sqlalchemy import select

        result = await db.execute(select(FleetSnapshot))
        assert len(list(result.scalars().all())) == 1


async def test_update_dashboard_trends_retention_persists_value(client):
    await client.get("/settings")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/settings/dashboard-trends-retention",
        data={"retention_days": "45", "csrf_token": csrf_token},
    )
    assert response.status_code == 303

    page = await client.get("/settings")
    assert 'value="45"' in page.text


async def test_dashboard_trends_api_endpoint(client, db_session_factory):
    async with db_session_factory() as db:
        db.add(
            FleetSnapshot(
                snapshot_date=date.today(),
                total_machines=3,
                online_machines=2,
                offline_machines=1,
                needs_updates=1,
                needs_security_updates=0,
                needs_reboot=1,
            )
        )
        await db.commit()

    headers = await _api_token(client)
    response = await client.get("/api/v1/dashboard/trends", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert len(data["snapshots"]) == 1
    assert data["snapshots"][0]["total_machines"] == 3
    assert data["snapshots"][0]["needs_reboot"] == 1
