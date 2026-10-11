"""Endpoint checks run from a managed machine (`app.services.remote_probes`):
the command each kind builds, how its output is read back, the job that
runs it, and the form and API that choose the machine."""

from __future__ import annotations

import re
import uuid
from typing import Any

import pytest
from httpx2 import AsyncClient
from sqlalchemy import select

from app.db.models.endpoint_check import EndpointCheck
from app.db.models.endpoint_check_result import EndpointCheckResult
from app.services import remote_probes
from app.services.endpoint_checks import ProbeResult
from app.tasks import jobs
from tests.test_homelab_round import _add_machine
from tests.test_update_history import _api_token

_DONE = "\n__DEBCONTROL_PROBE__ {rc} {ms}\n"


def _check(kind: str, target: str, **values: Any) -> EndpointCheck:
    return EndpointCheck(
        name="c", kind=kind, target=target, timeout_seconds=5, verify_tls=True, **values
    )


def test_commands_quote_the_target_and_time_themselves() -> None:
    http = remote_probes.build_command(_check("http", "https://intra.example/a b"))
    tcp = remote_probes.build_command(_check("tcp", "db.internal:5432"))
    tls = remote_probes.build_command(_check("tls", "intra.example"))
    dns = remote_probes.build_command(_check("dns", "intra.example@10.0.0.53"))
    plain_dns = remote_probes.build_command(_check("dns", "intra.example"))
    ping = remote_probes.build_command(_check("ping", "10.0.0.1"))

    assert "curl -sS -m 5 -o /dev/null" in http and "'https://intra.example/a b'" in http
    assert "/dev/tcp/db.internal/5432" in tcp and "timeout 5 bash -c" in tcp
    assert "openssl s_client -connect intra.example:443" in tls
    assert "-verify_return_error" in tls
    assert "dig +short" in dns and "@10.0.0.53" in dns
    assert "getent ahosts intra.example" in plain_dns
    assert "ping -c 1 -W 5 -- 10.0.0.1" in ping
    for command in (http, tcp, tls, dns, plain_dns, ping):
        assert "__DEBCONTROL_PROBE__ $rc" in command


def test_insecure_http_and_body_assertions_change_the_command() -> None:
    check = _check("http", "https://intra.example", expected_body="ok")
    check.verify_tls = False

    command = remote_probes.build_command(check)

    assert " -k " in command
    assert "--max-filesize" in command and "-o /dev/null" not in command


@pytest.mark.parametrize(
    ("check", "output", "ok", "error"),
    [
        (
            _check("http", "http://x"),
            "\n__DEBCONTROL_HTTP__ 200" + _DONE.format(rc=0, ms=42),
            True,
            None,
        ),
        (
            _check("http", "http://x"),
            "\n__DEBCONTROL_HTTP__ 503" + _DONE.format(rc=0, ms=9),
            False,
            "HTTP 503",
        ),
        (
            _check("http", "http://x", expected_status=204),
            "\n__DEBCONTROL_HTTP__ 200" + _DONE.format(rc=0, ms=9),
            False,
            "HTTP 200 (expected 204)",
        ),
        (
            _check("http", "http://x"),
            "curl: (7) Failed to connect\n__DEBCONTROL_HTTP__ 000" + _DONE.format(rc=7, ms=3),
            False,
            "curl: (7) Failed to connect",
        ),
        (
            _check("http", "http://x", expected_body="healthy"),
            "<p>degraded</p>\n__DEBCONTROL_HTTP__ 200" + _DONE.format(rc=0, ms=9),
            False,
            'the response doesn\'t contain "healthy"',
        ),
        (_check("ping", "10.0.0.1"), "64 bytes" + _DONE.format(rc=0, ms=2), True, None),
        (_check("ping", "10.0.0.1"), "" + _DONE.format(rc=1, ms=5000), False, "No reply."),
        (_check("tcp", "h:1"), "" + _DONE.format(rc=0, ms=1), True, None),
        (
            _check("tcp", "h:1"),
            "bash: connect: Connection refused" + _DONE.format(rc=1, ms=1),
            False,
            "bash: connect: Connection refused",
        ),
        (_check("dns", "x"), "10.0.0.7\nfe80::1" + _DONE.format(rc=0, ms=4), True, None),
        (_check("dns", "x"), "" + _DONE.format(rc=0, ms=4), False, "The name did not resolve."),
        (
            _check("dns", "x", expected_body="10.0.0.9"),
            "10.0.0.7" + _DONE.format(rc=0, ms=4),
            False,
            "Resolved to 10.0.0.7, expected 10.0.0.9.",
        ),
        (
            _check("http", "http://x"),
            "bash: curl: command not found" + _DONE.format(rc=127, ms=1),
            False,
            "curl is not installed on the machine.",
        ),
        (
            _check("ping", "x"),
            "connection dropped",
            False,
            "The probe did not finish on the machine.",
        ),
    ],
)
def test_output_is_read_back(
    check: EndpointCheck, output: str, ok: bool, error: str | None
) -> None:
    result = remote_probes.parse_output(check, output)

    assert (result.ok, result.error) == (ok, error)


def test_tls_reports_the_certificate_expiry_and_latency() -> None:
    good = remote_probes.parse_output(
        _check("tls", "x"), "notAfter=Jan  5 12:00:00 2099 GMT" + _DONE.format(rc=0, ms=31)
    )
    expired = remote_probes.parse_output(
        _check("tls", "x"), "notAfter=Jan  5 12:00:00 2001 GMT" + _DONE.format(rc=0, ms=31)
    )
    refused = remote_probes.parse_output(
        _check("tls", "x"),
        "verify error:num=18:self-signed certificate\nunable to load certificate"
        + _DONE.format(rc=1, ms=31),
    )

    assert good.ok and good.cert_expires_at is not None and good.cert_expires_at.year == 2099
    assert good.latency_ms == 31
    assert not expired.ok and expired.error == "The certificate has expired."
    assert not refused.ok and refused.error == "unable to load certificate"


async def test_job_runs_the_probe_on_the_source_machine(
    db_session_factory: Any, monkeypatch: Any
) -> None:
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    machine_id = await _add_machine(db_session_factory, name="jump")
    async with db_session_factory() as db:
        check = EndpointCheck(
            name="intranet",
            kind="http",
            target="http://intra.example",
            source_machine_id=machine_id,
            max_latency_ms=100,
        )
        db.add(check)
        await db.commit()
        check_id = check.id
    seen: list[str] = []

    async def fake_probe(
        check: Any, machine: Any, secret: Any, timeout_seconds: int
    ) -> ProbeResult:
        seen.append(machine.name)
        return ProbeResult(ok=True, status_code=200, latency_ms=250.0)

    async def server_probe(check: Any) -> ProbeResult:
        raise AssertionError("a check with a source machine must not run from the server")

    monkeypatch.setattr(jobs, "probe_from_machine", fake_probe)
    monkeypatch.setattr(jobs, "run_probe", server_probe)

    outcome = await jobs._run_endpoint_check(str(check_id))

    assert seen == ["jump"]
    # The latency limit applies to a probe run from a machine too.
    assert outcome == {"ok": True, "up": False}
    async with db_session_factory() as db:
        stored = (await db.execute(select(EndpointCheckResult))).scalar_one()
    assert stored.ok is False and "Too slow" in (stored.error or "")


async def test_unpinned_source_machine_is_a_failed_probe(db_session_factory: Any) -> None:
    machine_id = await _add_machine(db_session_factory, name="fresh", host_key_fingerprint=None)
    async with db_session_factory() as db:
        from app.db.models.machine import Machine

        machine = await db.get(Machine, machine_id)
        assert machine is not None

        result = await remote_probes.probe_from_machine(
            _check("ping", "10.0.0.1"), machine, None, 5
        )

    assert not result.ok and "no confirmed SSH host key" in (result.error or "")


async def test_form_and_api_choose_the_source_machine(
    client: AsyncClient, db_session_factory: Any, celery_calls: Any
) -> None:
    machine_id = await _add_machine(db_session_factory, name="jump")
    form = await client.get("/checks/new")
    match = re.search(r'name="csrf_token" value="([^"]+)"', form.text)
    assert match is not None
    data = {
        "csrf_token": match.group(1),
        "name": "intranet",
        "kind": "tcp",
        "target": "db.internal:5432",
        "interval_seconds": "300",
        "timeout_seconds": "10",
        "cert_warn_days": "14",
        "enabled": "1",
    }

    created = await client.post(
        "/checks/new", data={**data, "source_machine_id": str(machine_id)}, follow_redirects=False
    )
    unknown = await client.post(
        "/checks/new",
        data={**data, "name": "other", "source_machine_id": str(uuid.uuid4())},
        follow_redirects=False,
    )
    listing = await client.get("/checks")
    headers = await _api_token(client)
    api_list = (await client.get("/api/v1/checks", headers=headers)).json()
    api_bad = await client.post(
        "/api/v1/checks",
        headers=headers,
        json={
            "name": "x",
            "kind": "ping",
            "target": "10.0.0.1",
            "source_machine_id": str(uuid.uuid4()),
        },
    )

    assert f'<option value="{machine_id}"' in form.text
    assert created.status_code == 303
    assert unknown.status_code == 400
    assert "run from jump" in listing.text
    assert [c["source_machine_id"] for c in api_list] == [str(machine_id)]
    assert api_bad.status_code == 422
