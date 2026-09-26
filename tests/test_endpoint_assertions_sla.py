"""Endpoint checks: body/JSON/latency assertions and the monthly SLA report
(`app.services.endpoint_checks`, `app.services.endpoint_sla`)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from app.db.models.endpoint_check import EndpointCheck
from app.db.models.endpoint_check_result import EndpointCheckResult
from app.schemas.endpoint_check import EndpointCheckSave
from app.services.endpoint_checks import (
    BodyAssertions,
    ProbeResult,
    apply_latency_limit,
    evaluate_json_path,
    probe_http,
)
from app.services.endpoint_sla import load_sla_report, month_bounds, selectable_months
from tests.test_api_v1_extended import _api_token


def _mock_http(monkeypatch: pytest.MonkeyPatch, status: int, body: bytes) -> None:
    real_client = httpx.AsyncClient

    def _client(**kwargs: object) -> httpx.AsyncClient:
        transport = httpx.MockTransport(lambda request: httpx.Response(status, content=body))
        return real_client(transport=transport, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(httpx, "AsyncClient", _client)


@pytest.mark.parametrize(
    ("body", "path", "expected", "ok"),
    [
        ('{"status": "ok"}', "status", "ok", True),
        ('{"status": "degraded"}', "status", "ok", False),
        ('{"checks": {"db": {"ok": true}}}', "checks.db.ok", "true", True),
        ('{"checks": {"db": {"ok": false}}}', "checks.db.ok", None, False),
        ('{"items": [{"state": "up"}]}', "$.items.0.state", "up", True),
        ('{"count": 42}', "count", "42", True),
        ('{"count": 42}', "missing", None, False),
        ('{"value": null}', "value", None, False),
        ("<html>", "status", "ok", False),
    ],
)
def test_evaluate_json_path(body: str, path: str, expected: str | None, ok: bool) -> None:
    assert (evaluate_json_path(body, path, expected) is None) is ok


async def test_unexpected_body_fails_the_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    _mock_http(monkeypatch, 200, b"<h1>Internal Server Error</h1>")
    result = await probe_http(
        "http://svc.test/", 5, None, assertions=BodyAssertions(unexpected="Server Error")
    )
    assert not result.ok
    assert result.error is not None and 'contains "Server Error"' in result.error


async def test_json_assertion_through_the_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    _mock_http(monkeypatch, 200, b'{"status": "ok", "db": {"ok": true}}')
    ok = await probe_http(
        "http://svc.test/", 5, None,
        assertions=BodyAssertions(json_path="db.ok", json_expected="true"),
    )
    assert ok.ok
    bad = await probe_http(
        "http://svc.test/", 5, None,
        assertions=BodyAssertions(json_path="status", json_expected="down"),
    )
    assert not bad.ok
    assert bad.error is not None and "expected down" in bad.error


def test_latency_limit_turns_a_slow_success_into_a_failure() -> None:
    slow = apply_latency_limit(ProbeResult(ok=True, latency_ms=900.0), 500)
    assert not slow.ok and slow.error is not None and "Too slow" in slow.error
    fast = apply_latency_limit(ProbeResult(ok=True, latency_ms=100.0), 500)
    assert fast.ok
    unlimited = apply_latency_limit(ProbeResult(ok=True, latency_ms=9000.0), None)
    assert unlimited.ok


def test_schema_drops_http_assertions_for_tls_and_orphan_json_value() -> None:
    tls = EndpointCheckSave(
        name="c", kind="tls", target="example.com", unexpected_body="x", json_path="a",
        json_expected="b",
    )
    assert tls.unexpected_body is None and tls.json_path is None and tls.json_expected is None
    orphan = EndpointCheckSave(
        name="c", kind="http", target="https://example.com", json_expected="b"
    )
    assert orphan.json_expected is None


def test_month_bounds() -> None:
    now = datetime(2026, 9, 26, tzinfo=UTC)
    assert month_bounds("2026-08", now)[0] == "2026-08"
    key, start, end = month_bounds("2026-12", now)  # future -> current month
    assert key == "2026-09" and start == datetime(2026, 9, 1, tzinfo=UTC)
    assert end == datetime(2026, 10, 1, tzinfo=UTC)
    assert month_bounds("nonsense", now)[0] == "2026-09"
    assert month_bounds("2025-12", now)[2] == datetime(2026, 1, 1, tzinfo=UTC)
    assert selectable_months(now)[:2] == ["2026-09", "2026-08"]


async def _seed_results(db_session_factory, pattern: list[bool]) -> uuid.UUID:  # type: ignore[no-untyped-def]
    now = datetime.now(UTC)
    start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0) + timedelta(minutes=1)
    async with db_session_factory() as session:
        check = EndpointCheck(
            name="web", kind="http", target="https://example.com", interval_seconds=300,
            timeout_seconds=5, cert_warn_days=14, enabled=True, verify_tls=True,
            consecutive_failures=0, down_notified=False, sla_target_percent=99.0,
        )
        session.add(check)
        await session.flush()
        for index, ok in enumerate(pattern):
            session.add(
                EndpointCheckResult(
                    check_id=check.id, checked_at=start + timedelta(seconds=index), ok=ok
                )
            )
        await session.commit()
        return check.id


async def test_sla_report_counts_uptime_downtime_and_outages(db_session_factory) -> None:  # type: ignore[no-untyped-def]
    # up, down, down, up, down, up x5 -> 2 outages, 3 failed probes of 10.
    check_id = await _seed_results(
        db_session_factory, [True, False, False, True, False] + [True] * 5
    )
    async with db_session_factory() as session:
        report = await load_sla_report(session, "")
    (row,) = report.rows
    assert row.check_id == check_id
    assert row.probes == 10 and row.up == 7
    assert row.uptime_percent == 70.0
    assert row.outages == 2
    assert row.downtime_seconds == 3 * 300
    assert row.met is False


async def test_sla_report_first_probe_down_counts_as_an_outage(db_session_factory) -> None:  # type: ignore[no-untyped-def]
    await _seed_results(db_session_factory, [False, True, True])
    async with db_session_factory() as session:
        report = await load_sla_report(session, "")
    assert report.rows[0].outages == 1


async def test_sla_page_csv_and_api(client, db_session_factory) -> None:  # type: ignore[no-untyped-def]
    await _seed_results(db_session_factory, [True, True, False, True])

    page = await client.get("/checks/sla")
    assert page.status_code == 200
    assert "75.0 %" in page.text

    csv_response = await client.get("/checks/sla.csv")
    assert csv_response.status_code == 200
    assert csv_response.headers["content-type"].startswith("text/csv")
    assert "uptime_percent" in csv_response.text and ",75.0," in csv_response.text

    headers = await _api_token(client)
    api = await client.get("/api/v1/checks/sla", headers=headers)
    assert api.status_code == 200, api.text
    body = api.json()
    assert body["checks"][0]["outages"] == 1
    assert body["checks"][0]["sla_target_percent"] == 99.0


async def test_new_fields_round_trip_through_form_and_api(client, db_session_factory) -> None:  # type: ignore[no-untyped-def]
    await client.get("/checks")
    csrf = str(client.cookies.get("csrftoken"))
    response = await client.post(
        "/checks/new",
        data={
            "csrf_token": csrf, "name": "Health", "kind": "http",
            "target": "https://svc.test/health", "interval_seconds": "300",
            "timeout_seconds": "10", "cert_warn_days": "14", "verify_tls": "1",
            "enabled": "1", "unexpected_body": "maintenance", "json_path": "status",
            "json_expected": "ok", "max_latency_ms": "800", "sla_target_percent": "99,95",
        },
    )
    assert response.status_code == 303, response.text

    headers = await _api_token(client)
    (check,) = (await client.get("/api/v1/checks", headers=headers)).json()
    assert check["unexpected_body"] == "maintenance"
    assert check["json_path"] == "status" and check["json_expected"] == "ok"
    assert check["max_latency_ms"] == 800
    assert check["sla_target_percent"] == 99.95

    edit = await client.get(f"/checks/{check['id']}/edit")
    assert 'value="99.95"' in edit.text
