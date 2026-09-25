"""TLS/HTTP endpoint checks: target validation and the notification state
machine (`app.services.endpoint_checks`), the job, the Checks pages and
the REST API."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

import app.tasks.jobs as jobs
from app.db.models.endpoint_check import EndpointCheck
from app.db.models.notification_rule import NotificationEventType
from app.db.models.role import Permission
from app.services.endpoint_checks import (
    ProbeResult,
    apply_result,
    is_due,
    parse_tls_target,
    probe_tls,
    validate_target,
)
from tests.test_api_v1_extended import _api_token

NOW = datetime(2026, 9, 25, 12, 0, tzinfo=UTC)


def _check(**fields: object) -> EndpointCheck:
    check = EndpointCheck(
        id=uuid.uuid4(), name="site", kind="http", target="https://example.com",
        interval_seconds=300, timeout_seconds=5, cert_warn_days=14, enabled=True,
        verify_tls=True, consecutive_failures=0, down_notified=False,
    )
    for key, value in fields.items():
        setattr(check, key, value)
    return check


@pytest.mark.parametrize(
    ("kind", "target", "ok"),
    [
        ("http", "https://example.com/health", True),
        ("http", "example.com", False),
        ("http", "ftp://example.com", False),
        ("tls", "example.com", True),
        ("tls", "example.com:8443", True),
        ("tls", "https://example.com", False),
        ("tls", "example.com:99999", False),
        ("dns", "example.com", False),
    ],
)
def test_validate_target(kind, target, ok):
    assert (validate_target(kind, target) is None) is ok


def test_parse_tls_target():
    assert parse_tls_target("example.com") == ("example.com", 443)
    assert parse_tls_target("example.com:8443") == ("example.com", 8443)
    assert parse_tls_target("[::1]:993") == ("::1", 993)


def test_down_needs_two_failures_and_recovery_is_announced_once():
    check = _check()
    fail = ProbeResult(ok=False, error="Timed out.")

    assert apply_result(check, fail, NOW) == []
    events = apply_result(check, fail, NOW)
    assert [e for e, _ in events] == [NotificationEventType.ENDPOINT_DOWN]
    assert apply_result(check, fail, NOW) == []  # still down, no repeat

    events = apply_result(check, ProbeResult(ok=True, status_code=200), NOW)
    assert [e for e, _ in events] == [NotificationEventType.ENDPOINT_RECOVERED]
    assert check.consecutive_failures == 0
    assert apply_result(check, ProbeResult(ok=True), NOW) == []


def test_single_blip_never_notifies():
    check = _check()
    assert apply_result(check, ProbeResult(ok=False), NOW) == []
    assert apply_result(check, ProbeResult(ok=True), NOW) == []


def test_certificate_warning_once_per_certificate():
    check = _check(cert_warn_days=14)
    soon = NOW + timedelta(days=5)

    events = apply_result(check, ProbeResult(ok=True, cert_expires_at=soon), NOW)
    assert [e for e, _ in events] == [NotificationEventType.CERT_EXPIRING]
    assert events[0][1]["days"] == "5"
    assert apply_result(check, ProbeResult(ok=True, cert_expires_at=soon), NOW) == []

    renewed_but_soon = NOW + timedelta(days=10)
    events = apply_result(check, ProbeResult(ok=True, cert_expires_at=renewed_but_soon), NOW)
    assert [e for e, _ in events] == [NotificationEventType.CERT_EXPIRING]


def test_far_future_certificate_does_not_warn():
    check = _check()
    far = NOW + timedelta(days=80)
    assert apply_result(check, ProbeResult(ok=True, cert_expires_at=far), NOW) == []


def test_is_due():
    assert is_due(_check(last_checked_at=None), NOW)
    assert not is_due(_check(last_checked_at=NOW - timedelta(seconds=60)), NOW)
    assert is_due(_check(last_checked_at=NOW - timedelta(seconds=301)), NOW)
    assert not is_due(_check(enabled=False, last_checked_at=None), NOW)


async def test_probe_tls_reports_a_refused_connection():
    result = await probe_tls("127.0.0.1:1", timeout_seconds=2)

    assert result.ok is False
    assert result.error


async def test_job_stores_result_and_notifies(db_session_factory, monkeypatch):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    async with db_session_factory() as session:
        check = _check(consecutive_failures=1)
        session.add(check)
        await session.commit()
        check_id = check.id

    async def _fake_probe(check: EndpointCheck) -> ProbeResult:
        return ProbeResult(ok=False, error="HTTP 503", status_code=503)

    sent: list[NotificationEventType] = []

    async def _fake_notify(db, event_type, **kwargs):
        sent.append(event_type)

    monkeypatch.setattr(jobs, "run_probe", _fake_probe)
    monkeypatch.setattr(jobs, "notify", _fake_notify)

    result = await jobs._run_endpoint_check(str(check_id))

    assert result == {"ok": True, "up": False}
    assert sent == [NotificationEventType.ENDPOINT_DOWN]
    async with db_session_factory() as session:
        stored = await session.get(EndpointCheck, check_id)
        assert stored is not None
        assert stored.last_status_code == 503
        assert stored.down_notified is True


async def _csrf(client) -> str:  # type: ignore[no-untyped-def]
    await client.get("/checks")
    return str(client.cookies.get("csrftoken"))


async def test_create_check_via_form(client, db_session_factory, celery_calls):
    csrf = await _csrf(client)

    response = await client.post(
        "/checks/new",
        data={
            "csrf_token": csrf, "name": "Web", "kind": "http",
            "target": "https://example.com/", "interval_seconds": "300",
            "timeout_seconds": "10", "cert_warn_days": "14", "verify_tls": "1", "enabled": "1",
        },
    )

    assert response.status_code == 303
    assert celery_calls.names == ["app.tasks.jobs.run_endpoint_check"]
    async with db_session_factory() as session:
        (check,) = (await session.execute(select(EndpointCheck))).scalars().all()
        assert check.name == "Web"
    listing = await client.get("/checks")
    assert "https://example.com/" in listing.text


async def test_create_check_rejects_bad_target(client, db_session_factory):
    csrf = await _csrf(client)

    response = await client.post(
        "/checks/new",
        data={"csrf_token": csrf, "name": "Bad", "kind": "tls", "target": "https://x"},
    )

    assert response.status_code == 400
    assert "not a URL" in response.text


async def test_view_only_user_cannot_create(client, login_as):
    await login_as(client, permissions={Permission.MACHINE_VIEW})

    assert (await client.get("/checks")).status_code == 200
    assert (await client.get("/checks/new")).status_code == 403


async def test_api_crud(client, db_session_factory, celery_calls):
    headers = await _api_token(client)

    created = await client.post(
        "/api/v1/checks",
        json={"name": "Cert", "kind": "tls", "target": "example.com:443"},
        headers=headers,
    )
    assert created.status_code == 201, created.text
    check_id = created.json()["id"]

    listed = await client.get("/api/v1/checks", headers=headers)
    assert [c["id"] for c in listed.json()] == [check_id]

    bad = await client.post(
        "/api/v1/checks", json={"name": "X", "kind": "tls", "target": "https://x"}, headers=headers
    )
    assert bad.status_code == 422

    deleted = await client.delete(f"/api/v1/checks/{check_id}", headers=headers)
    assert deleted.status_code == 204


# --- expected_body (HTTP checks) ---


def _mock_http(monkeypatch: pytest.MonkeyPatch, status: int, body: bytes) -> None:
    import httpx

    real_client = httpx.AsyncClient

    def _client(**kwargs: object) -> httpx.AsyncClient:
        transport = httpx.MockTransport(lambda request: httpx.Response(status, content=body))
        return real_client(transport=transport, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(httpx, "AsyncClient", _client)


async def test_expected_body_present_is_up(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.services.endpoint_checks import probe_http

    _mock_http(monkeypatch, 200, b'{"status": "ok"}')
    result = await probe_http("http://svc.test/health", 5, None, expected_body='"ok"')
    assert result.ok
    assert result.status_code == 200


async def test_expected_body_missing_is_down_even_with_200(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.services.endpoint_checks import probe_http

    _mock_http(monkeypatch, 200, b"<h1>Down for maintenance</h1>")
    result = await probe_http("http://svc.test/health", 5, None, expected_body="ok")
    assert not result.ok
    assert result.error is not None and "doesn't contain" in result.error


async def test_no_expected_body_keeps_status_only_behavior(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.services.endpoint_checks import probe_http

    _mock_http(monkeypatch, 503, b"ok")
    result = await probe_http("http://svc.test/health", 5, None)
    assert not result.ok
    assert result.error == "HTTP 503"


def test_expected_body_is_dropped_for_tls_checks() -> None:
    from app.schemas.endpoint_check import EndpointCheckSave

    payload = EndpointCheckSave(
        name="cert", kind="tls", target="example.com:443", expected_body="ok"
    )
    assert payload.expected_body is None
    blank = EndpointCheckSave(
        name="web", kind="http", target="https://example.com", expected_body="   "
    )
    assert blank.expected_body is None


async def test_expected_body_round_trips_through_the_api(client):
    headers = await _api_token(client)
    created = await client.post(
        "/api/v1/checks",
        json={"name": "health", "kind": "http", "target": "https://svc.test/health",
              "expected_body": "ok"},
        headers=headers,
    )
    assert created.status_code == 201, created.text
    assert created.json()["expected_body"] == "ok"
