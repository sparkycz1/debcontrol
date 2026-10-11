"""Improvements taken over from honeypot-shelf: a failed update check is
visible with its error, a failed audit entry says why in every language,
tags can be added and removed in bulk from the machine list, and the
History tab leaves out look-ups and shows a terminal session as one entry."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Any

from httpx2 import AsyncClient
from sqlalchemy import select

from app.audit import log_event
from app.db.models.audit_log import AuditLogEntry, AuditOutcome
from app.db.models.machine import Machine
from app.services import machine_timeline
from app.ssh.exceptions import SSHConnectionError
from app.ssh.updates import UpdateCheckResult
from app.tasks import jobs
from app.web.templating import short_duration
from tests.test_homelab_round import _add_machine


def _result(exit_status: int, output: str) -> UpdateCheckResult:
    return UpdateCheckResult(
        exit_status=exit_status,
        upgradable_count=0,
        security_upgradable_count=0,
        flatpak_upgradable_count=0,
        snap_upgradable_count=0,
        output=output,
        held_packages=[],
    )


async def test_a_failed_update_check_keeps_its_error_until_one_succeeds(
    db_session_factory: Any, monkeypatch: Any
) -> None:
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    machine_id = await _add_machine(db_session_factory)
    answers: list[Any] = [
        _result(100, "Hit:1 http://deb.debian.org\nE: The repository is not signed.\n"),
        SSHConnectionError("Connection refused"),
        _result(0, "===APT_UPGRADABLE===\n"),
    ]

    async def fake_check(*args: object, **kwargs: object) -> UpdateCheckResult:
        answer = answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        assert isinstance(answer, UpdateCheckResult)
        return answer

    monkeypatch.setattr(jobs, "check_updates", fake_check)
    seen: list[str | None] = []
    for _ in range(3):
        await jobs._check_machine_updates(str(machine_id))
        async with db_session_factory() as db:
            machine = await db.get(Machine, machine_id)
            assert machine is not None
            seen.append(machine.updates_check_error)

    assert seen[0] is not None
    assert "status 100" in seen[0] and "not signed" in seen[0]
    assert seen[1] == "Connection refused"
    assert seen[2] is None


async def test_failed_check_shows_in_the_list_and_on_the_updates_tab(
    client: AsyncClient, db_session_factory: Any
) -> None:
    machine_id = await _add_machine(
        db_session_factory,
        updates_checked_at=datetime.now(UTC),
        updates_check_error="apt-get update exited with status 100.\nE: <broken>",
    )

    listing = await client.get("/machines")
    updates = await client.get(f"/machines/{machine_id}/updates")

    assert "check failed" in listing.text
    assert "The last update check failed:" in updates.text
    assert "E: &lt;broken&gt;" in updates.text
    assert "see the error above" not in updates.text


async def test_bulk_tags_from_the_machine_list(
    client: AsyncClient, db_session_factory: Any
) -> None:
    first = await _add_machine(db_session_factory, name="tag-a")
    second = await _add_machine(db_session_factory, name="tag-b", ip_address="10.0.0.9")
    page = await client.get("/machines")
    match = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    assert match is not None
    csrf = match.group(1)
    ids = [str(first), str(second)]

    assert 'formaction="/machines/bulk/tags/add"' in page.text
    assert 'formaction="/machines/bulk/tags/remove"' in page.text
    await client.post(
        "/machines/bulk/tags/add", data={"csrf_token": csrf, "machine_ids": ids, "tags": "dmz, lab"}
    )
    await client.post(
        "/machines/bulk/tags/remove",
        data={"csrf_token": csrf, "machine_ids": [str(first)], "tags": "lab"},
    )

    async with db_session_factory() as db:
        tags = {
            machine.name: sorted(tag.name for tag in machine.tags)
            for machine in (await db.execute(select(Machine))).scalars().all()
        }
    assert tags == {"tag-a": ["dmz"], "tag-b": ["dmz", "lab"]}


async def test_history_drops_look_ups_and_folds_a_terminal_session(
    db_session_factory: Any,
) -> None:
    machine_id = await _add_machine(db_session_factory)
    opened = datetime.now(UTC) - timedelta(hours=1)
    entries = [
        ("machine.terminal.open", opened, None),
        ("machine.terminal.close", opened + timedelta(seconds=720), {"duration_seconds": 720.4}),
        ("machine.terminal.open", opened + timedelta(minutes=30), None),  # still running
        ("machine.facts.refresh", opened + timedelta(minutes=5), None),
        ("machine.logs.follow", opened + timedelta(minutes=6), None),
        ("machine.power.reboot", opened + timedelta(minutes=7), None),
    ]
    async with db_session_factory() as db:
        for action, at, details in entries:
            db.add(
                AuditLogEntry(
                    actor="alice",
                    action=action,
                    summary=f"did {action}",
                    target_type="machine",
                    target_id=str(machine_id),
                    created_at=at,
                    details=details,
                )
            )
        await db.commit()
        machine = await db.get(Machine, machine_id)
        assert machine is not None

        timeline = await machine_timeline.load_timeline(
            db, machine, days=1, include_audit=True, kinds={"audit"}
        )

    actions = [event.data["action"] for event in timeline.events]
    assert actions == ["machine.terminal.open", "machine.power.reboot", "machine.terminal.session"]
    session = timeline.events[-1]
    assert session.data["duration_seconds"] == 720.4
    # Placed where the session started, not where it ended.
    assert abs((session.at - opened).total_seconds()) < 1
    assert short_duration(720.4) == "12 min"
    assert short_duration(45) == "45 s" and short_duration(7500) == "2 h 5 min"


async def test_audit_shows_the_reason_of_a_failure_in_czech(
    client: AsyncClient, db_session_factory: Any
) -> None:
    async with db_session_factory() as db:
        await log_event(
            db,
            actor="tester",
            action="user.create",
            summary='Rejected new user "bob": Passwords do not match.',
            outcome=AuditOutcome.FAILURE,
        )
    await client.get("/account")
    await client.post(
        "/account/locale",
        data={"csrf_token": client.cookies.get("csrftoken"), "locale": "cs"},
    )

    page = await client.get("/audit")

    assert '<html lang="cs"' in page.text
    assert "Passwords do not match." in page.text
