"""A machine's History tab (`app.services.machine_timeline`): notes,
detected changes, update runs, reachability transitions, audited actions
(only with `audit.view`), the notes API, and the AI summary prompts for a
machine's history and an endpoint check."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select

from app.audit import log_event
from app.db.models.ai_message import AiMessage
from app.db.models.endpoint_check import EndpointCheck
from app.db.models.endpoint_check_result import EndpointCheckResult
from app.db.models.machine_change import MachineChange
from app.db.models.machine_note import MachineNote
from app.db.models.machine_reachability_sample import MachineReachabilitySample
from app.db.models.machine_update_run import MachineUpdateRun, UpdateRunStatus, UpgradeStrategy
from app.db.models.role import Permission
from tests.test_ai_web import create_machine, setup_provider
from tests.test_api_v1_extended import _api_token


async def _seed_history(db_session_factory: Any, machine_id: uuid.UUID) -> None:
    now = datetime.now(UTC)
    async with db_session_factory() as db:
        db.add(
            MachineChange(
                machine_id=machine_id, detected_at=now - timedelta(hours=3), category="facts",
                field="kernel_version", old_value="6.1.0-25", new_value="6.1.0-26",
            )
        )
        db.add(
            MachineUpdateRun(
                machine_id=machine_id, strategy=UpgradeStrategy.DIST_UPGRADE,
                status=UpdateRunStatus.FAILED, error="dpkg was interrupted",
                finished_at=now - timedelta(hours=2),
            )
        )
        # up, up, down, down, up -> two transitions.
        for minutes, reachable in ((60, True), (50, True), (40, False), (30, False), (20, True)):
            db.add(
                MachineReachabilitySample(
                    machine_id=machine_id, checked_at=now - timedelta(minutes=minutes),
                    reachable=reachable,
                )
            )
        await db.commit()
        await log_event(
            db, action="machine.power.reboot", summary='Rebooted "web1"', actor="alice",
            target_type="machine", target_id=machine_id, target_label="web1",
        )
        await log_event(
            db, action="machine.logs.view", summary='Viewed journal on "web1"', actor="alice",
            target_type="machine", target_id=machine_id, target_label="web1",
        )


async def test_history_tab_merges_every_source(client, db_session_factory):
    machine_id = await create_machine(db_session_factory)
    await _seed_history(db_session_factory, machine_id)

    page = await client.get(f"/machines/{machine_id}/history")
    assert page.status_code == 200
    text = page.text
    assert "6.1.0-25" in text and "6.1.0-26" in text
    assert "dpkg was interrupted" in text
    assert "Stopped responding" in text and "Reachable again" in text
    assert "Rebooted" in text
    # Read-only audit entries are left out.
    assert "Viewed journal" not in text

    only_updates = await client.get(f"/machines/{machine_id}/history?kind=update_run")
    assert "dpkg was interrupted" in only_updates.text
    assert "6.1.0-26" not in only_updates.text


async def test_audit_entries_need_audit_view(client, login_as, db_session_factory):
    machine_id = await create_machine(db_session_factory)
    await _seed_history(db_session_factory, machine_id)
    await login_as(client, permissions={Permission.MACHINE_VIEW})

    page = await client.get(f"/machines/{machine_id}/history")
    assert page.status_code == 200
    assert "Rebooted" not in page.text
    assert "dpkg was interrupted" in page.text


async def test_notes_add_and_delete(client, db_session_factory):
    machine_id = await create_machine(db_session_factory)
    await client.get(f"/machines/{machine_id}/history")
    csrf = str(client.cookies.get("csrftoken"))

    added = await client.post(
        f"/machines/{machine_id}/notes", data={"csrf_token": csrf, "body": "Replaced the PSU"}
    )
    assert added.status_code == 303
    page = await client.get(f"/machines/{machine_id}/history")
    assert "Replaced the PSU" in page.text

    empty = await client.post(
        f"/machines/{machine_id}/notes", data={"csrf_token": csrf, "body": "   "}
    )
    assert "note_error=1" in empty.headers["location"]

    async with db_session_factory() as db:
        (note,) = (await db.execute(select(MachineNote))).scalars().all()
    deleted = await client.post(
        f"/machines/{machine_id}/notes/{note.id}/delete", data={"csrf_token": csrf}
    )
    assert deleted.status_code == 303
    async with db_session_factory() as db:
        assert (await db.execute(select(MachineNote))).scalars().all() == []


async def test_view_only_user_cannot_add_notes(client, login_as, db_session_factory):
    machine_id = await create_machine(db_session_factory)
    await login_as(client, permissions={Permission.MACHINE_VIEW})
    page = await client.get(f"/machines/{machine_id}/history")
    assert 'action="/machines/' + str(machine_id) + '/notes"' not in page.text
    csrf = str(client.cookies.get("csrftoken"))
    response = await client.post(
        f"/machines/{machine_id}/notes", data={"csrf_token": csrf, "body": "x"}
    )
    assert response.status_code == 403


async def test_timeline_and_notes_api(client, db_session_factory):
    machine_id = await create_machine(db_session_factory)
    await _seed_history(db_session_factory, machine_id)
    headers = await _api_token(client)

    created = await client.post(
        f"/api/v1/machines/{machine_id}/notes", json={"body": "Moved to rack B4"},
        headers=headers,
    )
    assert created.status_code == 201, created.text
    note_id = created.json()["id"]

    timeline = await client.get(f"/api/v1/machines/{machine_id}/timeline?days=7", headers=headers)
    assert timeline.status_code == 200, timeline.text
    body = timeline.json()
    kinds = {event["kind"] for event in body["events"]}
    assert kinds == {"note", "change", "update_run", "reachability", "audit"}
    assert body["includes_audit"] is True

    deleted = await client.delete(
        f"/api/v1/machines/{machine_id}/notes/{note_id}", headers=headers
    )
    assert deleted.status_code == 204
    missing = await client.delete(
        f"/api/v1/machines/{machine_id}/notes/{note_id}", headers=headers
    )
    assert missing.status_code == 404


async def test_ai_summary_of_a_machines_history(client, db_session_factory):
    machine_id = await create_machine(db_session_factory)
    await _seed_history(db_session_factory, machine_id)
    await setup_provider(db_session_factory)

    await client.get("/ai")
    csrf = str(client.cookies.get("csrftoken"))
    response = await client.post(
        "/ai/explain",
        data={"kind": "history", "machine_id": str(machine_id), "days": "7", "csrf_token": csrf},
    )
    assert response.status_code == 303, response.text
    async with db_session_factory() as db:
        (message,) = (await db.execute(select(AiMessage))).scalars().all()
    assert "dpkg was interrupted" in message.content
    assert "Kernel: 6.1.0-25 → 6.1.0-26" in message.content
    assert "Summarize what happened" in message.content


async def test_ai_summary_of_an_endpoint_check(client, db_session_factory):
    await setup_provider(db_session_factory)
    now = datetime.now(UTC)
    async with db_session_factory() as db:
        check = EndpointCheck(
            name="shop", kind="http", target="https://shop.test", interval_seconds=300,
            timeout_seconds=5, cert_warn_days=14, enabled=True, verify_tls=True,
            consecutive_failures=2, down_notified=True, last_ok=False, last_error="HTTP 502",
        )
        db.add(check)
        await db.flush()
        db.add(
            EndpointCheckResult(
                check_id=check.id, checked_at=now - timedelta(minutes=5), ok=False,
                status_code=502, error="HTTP 502",
            )
        )
        await db.commit()
        check_id = check.id

    await client.get("/ai")
    csrf = str(client.cookies.get("csrftoken"))
    response = await client.post(
        "/ai/explain",
        data={"kind": "endpoint_check", "check_id": str(check_id), "csrf_token": csrf},
    )
    assert response.status_code == 303, response.text
    async with db_session_factory() as db:
        (message,) = (await db.execute(select(AiMessage))).scalars().all()
    assert "currently DOWN" in message.content and "HTTP 502" in message.content
