"""Endpoint check result history: stored per probe, summarized on the
check's detail page and at /api/v1/checks/{id}/history, purged with the
monitoring retention."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select

import app.tasks.jobs as jobs
from app.core.app_settings import get_or_create_app_settings
from app.db.models.endpoint_check import EndpointCheck
from app.db.models.endpoint_check_result import EndpointCheckResult
from app.services.endpoint_check_history import build_check_history
from app.services.endpoint_checks import ProbeResult
from tests.test_api_v1_extended import _api_token


def _check() -> EndpointCheck:
    return EndpointCheck(
        name="api", kind="http", target="https://svc.test/health", interval_seconds=60,
        timeout_seconds=5, cert_warn_days=14, enabled=True, verify_tls=True,
        consecutive_failures=0, down_notified=False,
    )


async def _seed(db_session_factory, oks: list[bool]) -> uuid.UUID:
    now = datetime.now(UTC)
    async with db_session_factory() as session:
        check = _check()
        session.add(check)
        await session.flush()
        for i, ok in enumerate(oks):
            session.add(
                EndpointCheckResult(
                    check_id=check.id, checked_at=now - timedelta(minutes=len(oks) - i),
                    ok=ok, status_code=200 if ok else 503, latency_ms=100.0 + i,
                    error=None if ok else "HTTP 503",
                )
            )
        await session.commit()
        return check.id


def test_build_history_summarizes() -> None:
    now = datetime.now(UTC)
    rows = [
        EndpointCheckResult(check_id=uuid.uuid4(), checked_at=now, ok=ok, latency_ms=lat)
        for ok, lat in [(True, 10.0), (True, 20.0), (False, None), (True, 30.0)]
    ]
    history = build_check_history(rows, "1h")
    assert history.uptime_percent == 75.0
    assert history.failure_count == 1
    assert history.avg_latency_ms == 20.0
    assert history.p95_latency_ms == 30.0
    assert history.uptime_series == [100.0, 100.0, 0.0, 100.0]
    assert len(history.recent_failures) == 1


async def test_job_stores_a_result_row(db_session_factory, monkeypatch):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    async with db_session_factory() as session:
        check = _check()
        session.add(check)
        await session.commit()
        check_id = check.id

    async def _probe(check: EndpointCheck) -> ProbeResult:
        return ProbeResult(ok=True, status_code=200, latency_ms=42.0)

    async def _notify(*args: object, **kwargs: object) -> None:
        return None

    monkeypatch.setattr(jobs, "run_probe", _probe)
    monkeypatch.setattr(jobs, "notify", _notify)
    await jobs._run_endpoint_check(str(check_id))
    await jobs._run_endpoint_check(str(check_id))

    async with db_session_factory() as session:
        rows = (await session.execute(select(EndpointCheckResult))).scalars().all()
    assert len(rows) == 2
    assert all(r.check_id == check_id and r.ok and r.latency_ms == 42.0 for r in rows)


async def test_detail_page_and_api(client, db_session_factory):
    check_id = await _seed(db_session_factory, [True, True, False, True])
    page = await client.get(f"/checks/{check_id}?range_key=24h")
    assert page.status_code == 200
    assert "75.0 %" in page.text
    assert "HTTP 503" in page.text
    listing = await client.get("/checks")
    assert f'href="/checks/{check_id}"' in listing.text

    headers = await _api_token(client)
    api = await client.get(f"/api/v1/checks/{check_id}/history?range_key=24h", headers=headers)
    assert api.status_code == 200
    body = api.json()
    assert body["uptime_percent"] == 75.0
    assert body["sample_count"] == 4
    assert body["recent_failures"][0]["status_code"] == 503


async def test_purge_drops_results_past_retention(db_session_factory, monkeypatch):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    check_id = await _seed(db_session_factory, [True])
    async with db_session_factory() as session:
        session.add(
            EndpointCheckResult(
                check_id=check_id, checked_at=datetime.now(UTC) - timedelta(days=400), ok=True
            )
        )
        app_settings = await get_or_create_app_settings(session)
        app_settings.monitoring_history_retention_days = 90
        await session.commit()

    await jobs._purge_old_monitoring_samples()

    async with db_session_factory() as session:
        remaining = (await session.execute(select(EndpointCheckResult))).scalars().all()
    assert len(remaining) == 1
