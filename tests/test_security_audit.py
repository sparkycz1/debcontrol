"""Lynis security audits: the remote script and its report parser
(`app.ssh.lynis`), the background job, the Security tab, Security -> Audit,
the REST API and the scheduled action."""

from __future__ import annotations

import subprocess
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from httpx2 import AsyncClient
from sqlalchemy import select

from app.db.models.audit_log import AuditLogEntry
from app.db.models.machine import Machine
from app.db.models.security_audit import SecurityAudit, SecurityAuditStatus
from app.scheduling.actions import get_action
from app.scheduling.builtin_actions import register_builtin_actions
from app.services import security_audit
from app.ssh import lynis
from app.ssh.lynis import LynisResult, build_audit_command, parse_audit_output
from app.ssh.onboarding import SUDO_COMMANDS
from app.tasks import jobs
from tests.test_homelab_round import _add_machine
from tests.test_update_history import _api_token

_OUTPUT = f"""{lynis.PRIVILEGED_MARKER}
{lynis.EXIT_MARKER}0
{lynis.REPORT_DELIMITER}
lynis_version=3.0.9
warning[]=SSH-7408|Root can log in over SSH|PermitRootLogin|-|
warning[]=SSH-7408|Root can log in over SSH|PermitRootLogin|-|
warning[]=FIRE-4512|iptables module(s) loaded, but no rules active|-|-|
suggestion[]=DEB-0880|Install fail2ban|-|-|
suggestion[]=KRNL-6000|One or more sysctl values differ|sysctl key|Set it in /etc/sysctl.d|
suggestion[]=|no test id|-|-|
lynis_tests_done=241
hardening_index=57
{lynis.OUTPUT_DELIMITER}
"""


def test_the_report_is_parsed_into_findings() -> None:
    result = parse_audit_output(_OUTPUT)

    assert result.privileged is True and result.exit_status == 0
    assert (result.version, result.hardening_index, result.tests_done) == ("3.0.9", 57, 241)
    # The duplicate is reported once; "-" is an empty field.
    assert result.warnings == [
        {
            "test": "SSH-7408",
            "text": "Root can log in over SSH",
            "detail": "PermitRootLogin",
            "solution": "",
        },
        {
            "test": "FIRE-4512",
            "text": "iptables module(s) loaded, but no rules active",
            "detail": "",
            "solution": "",
        },
    ]
    assert [s["test"] for s in result.suggestions] == ["DEB-0880", "KRNL-6000"]
    assert result.suggestions[1]["solution"] == "Set it in /etc/sysctl.d"
    assert result.usable


def test_missing_lynis_and_a_failed_run_are_told_apart() -> None:
    missing = parse_audit_output(f"{lynis.INSTALL_FAILED_MARKER}\n{lynis.MISSING_MARKER}\n")
    failed = parse_audit_output(
        f"{lynis.UNPRIVILEGED_MARKER}\n{lynis.EXIT_MARKER}1\n{lynis.REPORT_DELIMITER}\n"
        f"{lynis.OUTPUT_DELIMITER}\nFatal error: something\n"
    )

    assert missing.missing and missing.install_failed and not missing.usable
    assert failed.privileged is False and failed.exit_status == 1
    assert not failed.usable and failed.output == "Fatal error: something"


def test_the_script_is_valid_shell_and_installs_only_when_asked() -> None:
    plain = build_audit_command(install_if_missing=False)
    install = build_audit_command(install_if_missing=True)

    for command in (plain, install):
        subprocess.run(["sh", "-n", "-c", command], check=True)  # noqa: S603, S607
        assert 'sudo -n -l "$L"' in command and "--report-file" in command
    assert "apt-get" not in plain
    assert "sudo -n apt-get -y -q install lynis" in install
    # Lynis can only run as root through a grant for its exact path.
    assert "/usr/sbin/lynis" in SUDO_COMMANDS


def _fake_result(**kw: Any) -> LynisResult:
    result = parse_audit_output(_OUTPUT)
    for key, value in kw.items():
        setattr(result, key, value)
    return result


async def _run_job(monkeypatch: Any, result: LynisResult, audit_id: uuid.UUID) -> list[bool]:
    calls: list[bool] = []

    async def fake_run(machine: Any, secret: Any, *, install_if_missing: bool, **_kw: Any) -> Any:
        calls.append(install_if_missing)
        return result

    monkeypatch.setattr(jobs, "run_lynis_audit", fake_run)
    await jobs._run_security_audit(str(audit_id))
    return calls


async def test_the_job_keeps_the_report_and_prunes_old_audits(
    db_session_factory: Any, monkeypatch: Any
) -> None:
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    machine_id = await _add_machine(db_session_factory, name="web1")
    old = datetime.now(UTC) - timedelta(days=30)
    async with db_session_factory() as db:
        for i in range(security_audit.KEEP_PER_MACHINE + 2):
            db.add(
                SecurityAudit(
                    machine_id=machine_id,
                    status=SecurityAuditStatus.SUCCEEDED,
                    hardening_index=50,
                    created_at=old + timedelta(hours=i),
                )
            )
        audit = SecurityAudit(
            machine_id=machine_id, install_if_missing=True, created_at=datetime.now(UTC)
        )
        db.add(audit)
        await db.commit()

    calls = await _run_job(monkeypatch, _fake_result(), audit.id)

    async with db_session_factory() as db:
        stored = await db.get(SecurityAudit, audit.id)
        count = len((await db.execute(select(SecurityAudit))).scalars().all())
    assert calls == [True]
    assert stored is not None and stored.status == SecurityAuditStatus.SUCCEEDED
    assert stored.hardening_index == 57 and stored.privileged is True
    assert len(stored.warnings or []) == 2 and stored.error is None
    assert count == security_audit.KEEP_PER_MACHINE


async def test_the_job_fails_when_lynis_is_missing(
    db_session_factory: Any, monkeypatch: Any
) -> None:
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    machine_id = await _add_machine(db_session_factory, name="web2")
    async with db_session_factory() as db:
        audit = SecurityAudit(machine_id=machine_id, created_at=datetime.now(UTC))
        db.add(audit)
        await db.commit()

    await _run_job(monkeypatch, LynisResult(missing=True), audit.id)

    async with db_session_factory() as db:
        stored = await db.get(SecurityAudit, audit.id)
    assert stored is not None and stored.status == SecurityAuditStatus.FAILED
    assert stored.error == "Lynis is not installed on this machine."


def test_a_run_that_never_finished_shows_as_interrupted() -> None:
    now = datetime.now(UTC)
    fresh = SecurityAudit(status=SecurityAuditStatus.RUNNING, started_at=now, created_at=now)
    stuck = SecurityAudit(
        status=SecurityAuditStatus.RUNNING,
        started_at=now - timedelta(days=1),
        created_at=now - timedelta(days=1),
    )

    assert security_audit.display_status(fresh) == "running" and security_audit.is_active(fresh)
    assert security_audit.display_status(stuck) == "interrupted"
    assert not security_audit.is_active(stuck)


async def test_auditing_from_the_pages_the_api_and_a_schedule(
    client: AsyncClient, db_session_factory: Any, celery_calls: Any
) -> None:
    machine_id = await _add_machine(db_session_factory, name="db1")
    no_key = await _add_machine(db_session_factory, name="fresh", host_key_fingerprint=None)
    async with db_session_factory() as db:
        db.add(
            SecurityAudit(
                machine_id=machine_id,
                status=SecurityAuditStatus.SUCCEEDED,
                hardening_index=64,
                lynis_version="3.0.9",
                privileged=False,
                warnings=[
                    {"test": "SSH-7408", "text": "Root login allowed", "detail": "", "solution": ""}
                ],
                suggestions=[],
                created_at=datetime.now(UTC) - timedelta(days=2),
                finished_at=datetime.now(UTC) - timedelta(days=2),
            )
        )
        await db.commit()

    tab = await client.get(f"/machines/{machine_id}/security")
    never = await client.get(f"/machines/{no_key}/security")
    csrf = client.cookies.get("csrftoken")
    started = await client.post(
        f"/machines/{machine_id}/security/audit",
        data={"csrf_token": csrf, "install": "on"},
        follow_redirects=False,
    )
    again = await client.post(
        f"/machines/{machine_id}/security/audit",
        data={"csrf_token": csrf},
        follow_redirects=False,
    )
    running = await client.get(f"/machines/{machine_id}/security", headers={"HX-Request": "true"})
    fleet = await client.get("/security/audit")
    bulk = await client.post(
        "/security/audit/run", data={"csrf_token": csrf}, follow_redirects=False
    )
    headers = await _api_token(client)
    api_list = await client.get("/api/v1/security-audits", headers=headers)
    api_history = await client.get(
        f"/api/v1/machines/{machine_id}/security-audits", headers=headers
    )
    api_busy = await client.post(
        f"/api/v1/machines/{machine_id}/security-audits", headers=headers, json={}
    )

    assert tab.status_code == 200
    assert "Root login allowed" in tab.text and "SSH-7408" in tab.text
    assert "without root" in tab.text and "Run audit now" in tab.text
    assert "has not been audited yet" in never.text
    assert started.status_code == 303 and "audit_error" not in started.headers["location"]
    assert again.status_code == 303 and "audit_error=" in again.headers["location"]
    assert 'hx-trigger="every 5s"' in running.text and "<html" not in running.text
    assert fleet.status_code == 200 and "db1" in fleet.text and "fresh" in fleet.text
    # db1 is busy and "fresh" has no host key: nothing new to start.
    assert bulk.headers["location"] == "/security/audit?started=0&skipped=2"
    assert celery_calls.names.count("app.tasks.jobs.run_security_audit") == 1
    rows = {row["machine_name"]: row for row in api_list.json()}
    assert rows["db1"]["audit"]["hardening_index"] == 64
    assert rows["db1"]["latest"]["status"] == "pending"
    assert rows["fresh"]["audit"] is None
    assert [a["status"] for a in api_history.json()] == ["pending", "succeeded"]
    assert api_history.json()[1]["warnings"][0]["test"] == "SSH-7408"
    assert api_busy.status_code == 409

    async with db_session_factory() as db:
        pending = (
            await db.execute(select(SecurityAudit).where(SecurityAudit.status == "pending"))
        ).scalar_one()
        actions = list((await db.execute(select(AuditLogEntry.action))).scalars().all())
        # The stuck run no longer blocks: a schedule starts a fresh one.
        pending.created_at = datetime.now(UTC) - timedelta(days=1)
        await db.commit()
        machines = list((await db.execute(select(Machine))).scalars().all())
        register_builtin_actions()
        action = get_action("security_audit")
        assert action is not None
        result = await action.run(db, machines, {"install": "yes"})
    assert pending.install_if_missing is True
    assert actions.count("machine.security_audit.run") == 3
    assert actions.count("machines.bulk.security_audit.run") == 1
    assert (result.attempted, result.skipped) == (1, 1)
    assert celery_calls.names.count("app.tasks.jobs.run_security_audit") == 2
