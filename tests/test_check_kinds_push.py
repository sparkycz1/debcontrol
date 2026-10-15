"""SMTP, SSH and push (heartbeat) checks: the probes against small local
servers, the push state machine, the `/push/<token>` address, and the
status page's response time, daily history and notice."""

from __future__ import annotations

import asyncio
import subprocess
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx2 import AsyncClient
from pydantic import ValidationError
from sqlalchemy import select

import app.tasks.jobs as jobs
from app.core.app_settings import get_or_create_app_settings
from app.db.models.endpoint_check import EndpointCheck
from app.db.models.endpoint_check_result import EndpointCheckResult
from app.db.models.machine_reachability_sample import MachineReachabilitySample
from app.db.models.notification_rule import NotificationEventType
from app.schemas.endpoint_check import EndpointCheckSave
from app.services import network_probes, remote_probes, status_page
from app.services.endpoint_checks import (
    ProbeResult,
    apply_result,
    evaluate_push,
    is_due,
    probe_smtp,
    push_grace_seconds,
    push_overdue,
    sync_push_token,
)
from tests.test_homelab_round import _add_machine
from tests.test_update_history import _api_token

NOW = datetime(2026, 10, 15, 12, 0, tzinfo=UTC)

Handler = Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]


@asynccontextmanager
async def _server(handler: Handler) -> AsyncIterator[int]:
    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        yield port
    finally:
        server.close()
        await server.wait_closed()


def _push_check(**fields: Any) -> EndpointCheck:
    check = EndpointCheck(
        id=uuid.uuid4(), name="backup", kind="push", target="", interval_seconds=3600,
        timeout_seconds=10, cert_warn_days=14, enabled=True, verify_tls=True,
        consecutive_failures=0, down_notified=False, created_at=NOW - timedelta(days=1),
    )
    for key, value in fields.items():
        setattr(check, key, value)
    return check


# --- SSH -------------------------------------------------------------------------


async def test_ssh_probe_reads_the_banner_and_checks_the_expected_text() -> None:
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(b"Welcome\r\nSSH-2.0-OpenSSH_9.6p1 Debian\r\n")
        await writer.drain()
        await asyncio.sleep(2)  # like sshd: waits for the client's banner
        writer.close()

    async with _server(handler) as port:
        ok = await network_probes.probe_ssh(f"127.0.0.1:{port}", 5, "OpenSSH_9")
        wrong = await network_probes.probe_ssh(f"127.0.0.1:{port}", 5, "dropbear")

    assert ok[0] is True and ok[2] is not None and ok[2] < 2000
    assert wrong[0] is False and "dropbear" in (wrong[1] or "")


async def test_ssh_probe_fails_on_a_service_that_is_not_ssh() -> None:
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
        await writer.drain()
        writer.close()

    async with _server(handler) as port:
        ok, error, _latency = await network_probes.probe_ssh(f"127.0.0.1:{port}", 5, None)

    assert ok is False and "not with an SSH banner" in (error or "")


def test_ssh_from_a_machine_parses_the_banner() -> None:
    check = EndpointCheck(kind="ssh", target="nas.lan", timeout_seconds=5, expected_body=None)
    command = remote_probes.build_command(check)
    up = remote_probes.parse_output(
        check, "SSH-2.0-OpenSSH_9.6\n\n__DEBCONTROL_PROBE__ 0 12\n"
    )
    down = remote_probes.parse_output(
        check, "bash: connect: Connection refused\n\n__DEBCONTROL_PROBE__ 1 3\n"
    )

    assert "/dev/tcp/nas.lan/22" in command
    assert up.ok and up.latency_ms == 12.0
    assert not down.ok and "refused" in (down.error or "")


@pytest.mark.parametrize("kind", ["tcp", "ssh"])
def test_tcp_and_ssh_quote_the_host_inside_bash(kind: str, tmp_path: Any) -> None:
    marker = tmp_path / "ran"
    check = EndpointCheck(kind=kind, target=f"a$(touch {marker}):22", timeout_seconds=2)
    subprocess.run(  # noqa: S603 - the command under test, run locally
        ["bash", "-c", remote_probes.build_command(check)],  # noqa: S607
        capture_output=True,
        check=False,
    )
    assert not marker.exists()


# --- SMTP ------------------------------------------------------------------------


def _smtp_handler(*, greeting: bytes = b"220 mail.test ESMTP\r\n") -> Handler:
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(greeting)
        await writer.drain()
        while line := await reader.readline():
            command = line.strip().upper()
            if command.startswith(b"EHLO"):
                writer.write(b"250-mail.test\r\n250-SIZE 1000\r\n250 8BITMIME\r\n")
            elif command == b"QUIT":
                writer.write(b"221 bye\r\n")
                await writer.drain()
                break
            else:
                writer.write(b"502 no\r\n")
            await writer.drain()
        writer.close()

    return handler


async def test_smtp_probe_without_starttls_is_up_without_a_certificate() -> None:
    async with _server(_smtp_handler()) as port:
        result = await probe_smtp(f"127.0.0.1:{port}", 5)

    assert result.ok, result.error
    assert result.cert_expires_at is None and result.latency_ms is not None


async def test_smtp_probe_fails_on_a_refusing_greeting() -> None:
    async with _server(_smtp_handler(greeting=b"554 go away\r\n")) as port:
        result = await probe_smtp(f"127.0.0.1:{port}", 5)

    assert not result.ok and "554" in (result.error or "")


async def test_smtp_probe_reports_a_refused_connection() -> None:
    result = await probe_smtp("127.0.0.1:1", 2)
    assert not result.ok and result.error


def test_smtp_and_push_cannot_run_from_a_machine() -> None:
    for kind, target in (("smtp", "mail.example.com"), ("push", "")):
        with pytest.raises(ValidationError, match="debcontrol server only"):
            EndpointCheckSave(name="x", kind=kind, target=target, source_machine_id=uuid.uuid4())
    ssh = EndpointCheckSave(
        name="x", kind="ssh", target="nas.lan", expected_body="OpenSSH",
        source_machine_id=uuid.uuid4(),
    )
    assert ssh.expected_body == "OpenSSH"


# --- Push: state machine ---------------------------------------------------------------


def test_push_token_follows_the_kind() -> None:
    check = _push_check()
    sync_push_token(check)
    token = check.push_token
    sync_push_token(check)
    assert token and check.push_token == token  # kept on edit

    check.kind = "tcp"
    check.last_push_at = NOW
    sync_push_token(check)
    assert check.push_token is None and check.last_push_at is None


def test_push_is_overdue_after_the_interval_and_grace() -> None:
    grace = push_grace_seconds(_push_check())
    assert grace == 360  # a tenth of an hour
    assert push_grace_seconds(_push_check(interval_seconds=300)) == 60  # at least a minute

    fresh = _push_check(last_push_at=NOW - timedelta(seconds=3600 + grace - 1))
    late = _push_check(last_push_at=NOW - timedelta(seconds=3600 + grace + 1))
    assert not push_overdue(fresh, NOW) and push_overdue(late, NOW)

    # Nothing yet: counted from when the check was created.
    new = _push_check(created_at=NOW - timedelta(minutes=5))
    assert evaluate_push(new, NOW) is None
    never = evaluate_push(_push_check(), NOW)
    assert never is not None and not never.ok


def test_one_missed_heartbeat_is_an_outage() -> None:
    check = _push_check(last_push_at=NOW - timedelta(hours=3))
    missed = evaluate_push(check, NOW)
    assert missed is not None and not missed.ok and "No heartbeat since" in (missed.error or "")

    events = apply_result(check, missed, NOW)
    assert [e for e, _ in events] == [NotificationEventType.ENDPOINT_DOWN]
    events = apply_result(check, ProbeResult(ok=True), NOW)
    assert [e for e, _ in events] == [NotificationEventType.ENDPOINT_RECOVERED]


def test_push_is_due_only_while_overdue() -> None:
    on_time = _push_check(last_push_at=NOW - timedelta(minutes=10), last_checked_at=None)
    late = _push_check(
        last_push_at=NOW - timedelta(hours=2), last_checked_at=NOW - timedelta(hours=2)
    )
    just_recorded = _push_check(
        last_push_at=NOW - timedelta(hours=2), last_checked_at=NOW - timedelta(minutes=1)
    )
    assert not is_due(on_time, NOW)
    assert is_due(late, NOW)
    assert not is_due(just_recorded, NOW)


# --- Push: the address and the job ---------------------------------------------------------


async def _csrf(client: AsyncClient) -> str:
    await client.get("/checks")
    return str(client.cookies.get("csrftoken"))


async def test_push_check_end_to_end(
    client: AsyncClient, db_session_factory: Any, celery_calls: Any, monkeypatch: Any
) -> None:
    csrf = await _csrf(client)
    created = await client.post(
        "/checks/new",
        data={
            "csrf_token": csrf, "name": "Nightly backup", "kind": "push", "target": "",
            "interval_seconds": "86400", "timeout_seconds": "10", "cert_warn_days": "14",
            "enabled": "1",
        },
        follow_redirects=False,
    )
    assert created.status_code == 303, created.text
    assert celery_calls.names == []  # nothing to probe
    async with db_session_factory() as db:
        check = (await db.execute(select(EndpointCheck))).scalar_one()
        token = check.push_token
    assert token and created.headers["location"] == f"/checks/{check.id}"
    detail = await client.get(f"/checks/{check.id}")
    assert f"/push/{token}" in detail.text

    # Called by a script: no session, any network.
    client.cookies.clear()
    up = await client.get(f"/push/{token}")
    down = await client.post(f"/push/{token}?status=down&msg=disk+full")
    unknown = await client.get("/push/not-a-token")
    assert (up.status_code, down.status_code, unknown.status_code) == (200, 200, 404)
    assert up.text == "OK\n"
    pushes = [c for c in celery_calls if c[0] == "app.tasks.jobs.receive_endpoint_push"]
    assert [c[1][1:3] for c in pushes] == [(True, None), (False, "disk full")]

    # The task records it like a probe result.
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    sent: list[NotificationEventType] = []

    async def _fake_notify(db: Any, event_type: NotificationEventType, **kwargs: Any) -> None:
        sent.append(event_type)

    monkeypatch.setattr(jobs, "notify", _fake_notify)
    await jobs._receive_endpoint_push(*pushes[1][1])
    async with db_session_factory() as db:
        stored = await db.get(EndpointCheck, check.id)
        results = (await db.execute(select(EndpointCheckResult))).scalars().all()
    assert stored is not None and stored.last_ok is False
    assert stored.last_error == "Reported down: disk full" and stored.last_push_at is not None
    assert len(results) == 1 and sent == [NotificationEventType.ENDPOINT_DOWN]

    # A "run now" while the last heartbeat is fresh keeps its verdict.
    assert await jobs._run_endpoint_check(str(check.id)) == {"ok": True, "up": False}


async def test_disabled_or_rotated_push_address_is_gone(
    client: AsyncClient, db_session_factory: Any
) -> None:
    headers = await _api_token(client)
    created = await client.post(
        "/api/v1/checks",
        json={"name": "cron", "kind": "push", "interval_seconds": 600},
        headers=headers,
    )
    assert created.status_code == 201, created.text
    body = created.json()
    old_path = body["push_path"]
    listed = (await client.get("/api/v1/checks", headers=headers)).json()
    assert "push_path" not in listed[0]  # the secret only goes to machine.manage answers

    rotated = await client.post(f"/api/v1/checks/{body['id']}/push-token", headers=headers)
    assert rotated.status_code == 200 and rotated.json()["push_path"] != old_path
    assert (await client.get(old_path)).status_code == 404
    new_path = rotated.json()["push_path"]
    assert (await client.get(new_path)).status_code == 200

    async with db_session_factory() as db:
        check = await db.get(EndpointCheck, uuid.UUID(body["id"]))
        assert check is not None
        check.enabled = False
        await db.commit()
    assert (await client.get(new_path)).status_code == 404

    not_push = await client.post(
        "/api/v1/checks", json={"name": "t", "kind": "tcp", "target": "nas.lan:22"},
        headers=headers,
    )
    assert not_push.json()["push_path"] is None
    refused = await client.post(
        f"/api/v1/checks/{not_push.json()['id']}/push-token", headers=headers
    )
    assert refused.status_code == 422


# --- Status page extras --------------------------------------------------------------------


async def test_status_page_response_time_history_and_notice(
    client: AsyncClient, db_session_factory: Any
) -> None:
    now = datetime.now(UTC)
    web = await _add_machine(
        db_session_factory, name="Web server", ip_address="203.0.113.20", is_reachable=True
    )
    async with db_session_factory() as db:
        shop = EndpointCheck(
            name="Shop", kind="http", target="https://shop.example", last_ok=True,
            last_latency_ms=120.0, enabled=True,
        )
        db.add(shop)
        await db.flush()
        for hours, latency in ((1, 100.0), (2, 140.0)):
            db.add(EndpointCheckResult(
                check_id=shop.id, checked_at=now - timedelta(hours=hours), ok=True,
                latency_ms=latency,
            ))
        db.add(EndpointCheckResult(
            check_id=shop.id, checked_at=now - timedelta(days=3), ok=False, latency_ms=None
        ))
        db.add(MachineReachabilitySample(
            machine_id=web, checked_at=now - timedelta(minutes=1), reachable=True, latency_ms=4.0
        ))
        await db.commit()
        shop_id = shop.id
    headers = await _api_token(client)
    status_page.invalidate()

    plain = (
        await client.put(
            "/api/v1/status-page", headers=headers,
            json={"enabled": True, "check_ids": [str(shop_id)], "machine_ids": [str(web)]},
        )
    ).json()
    plain_data = (await client.get(f"{plain['path']}.json")).json()
    assert "latency_ms" not in plain_data["items"][0] and "days" not in plain_data["items"][0]

    status_page.invalidate()
    full = (
        await client.put(
            "/api/v1/status-page", headers=headers,
            json={
                "enabled": True, "check_ids": [str(shop_id)], "machine_ids": [str(web)],
                "show_latency": True, "show_history": True,
                "message": "Planned maintenance on Saturday",
            },
        )
    ).json()
    assert full["show_latency"] and full["show_history"]
    data = (await client.get(f"{full['path']}.json")).json()
    page = await client.get(full["path"])

    shop_item, web_item = data["items"]
    assert data["message"] == "Planned maintenance on Saturday"
    assert shop_item["latency_ms"] == 120.0 and shop_item["avg_latency_ms_24h"] == 120.0
    assert web_item["latency_ms"] == 4.0
    assert len(shop_item["days"]) == status_page.WINDOW_DAYS
    assert shop_item["days"][-1]["date"] == now.date().isoformat()
    bad_day = (now - timedelta(days=3)).date().isoformat()
    assert {"date": bad_day, "uptime_percent": 0.0} in shop_item["days"]
    assert "Planned maintenance on Saturday" in page.text
    assert "status-day-down" in page.text and "Response time" in page.text
    assert "shop.example" not in page.text


async def test_status_page_settings_form_saves_the_extras(
    client: AsyncClient, db_session_factory: Any
) -> None:
    await client.get("/checks/status-page")
    csrf = client.cookies.get("csrftoken")
    saved = await client.post(
        "/checks/status-page",
        data={
            "csrf_token": csrf, "enabled": "true", "show_latency": "true",
            "message": "  Upgrading the database tonight  ",
        },
        follow_redirects=False,
    )
    assert saved.status_code == 303
    async with db_session_factory() as db:
        settings = await get_or_create_app_settings(db)
        assert settings.status_page_show_latency is True
        assert settings.status_page_show_history is False
        assert settings.status_page_message == "Upgrading the database tonight"
