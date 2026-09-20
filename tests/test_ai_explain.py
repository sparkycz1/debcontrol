"""The "Ask AI why" button — `POST /ai/explain` — on a failed update run
and on a machine's readiness banner. Starts a brand-new AI conversation
whose first message is server-built from the failure/finding, with no
provider contacted (the autouse `celery_calls` fixture fakes
`ai_jobs.run_ai_turn.delay`, so the actual reply never runs here — this
only checks that the right conversation/first message gets created).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from app.db.models.machine import Machine
from app.db.models.machine_update_run import MachineUpdateRun, UpdateRunStatus, UpgradeStrategy
from app.db.models.role import Permission
from tests.test_ai_web import ALL_AI_PERMISSIONS, create_machine, setup_provider


async def _create_failed_run(
    db_session_factory: Any, machine_id: uuid.UUID, *, error: str = "", output: str = ""
) -> uuid.UUID:
    async with db_session_factory() as db:
        run = MachineUpdateRun(
            machine_id=machine_id,
            strategy=UpgradeStrategy.DIST_UPGRADE,
            status=UpdateRunStatus.FAILED,
            error=error or None,
            output=output or None,
            finished_at=datetime.now(UTC),
        )
        db.add(run)
        await db.commit()
        return run.id


async def test_explain_a_failed_update_run(client, db_session_factory):
    machine_id = await create_machine(db_session_factory)
    _provider_id, _model_id = await setup_provider(db_session_factory)
    run_id = await _create_failed_run(
        db_session_factory, machine_id, error="apt-get exited 100", output="E: Unable to fetch"
    )

    await client.get("/ai")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/ai/explain",
        data={
            "kind": "update_run",
            "machine_id": str(machine_id),
            "run_id": str(run_id),
            "csrf_token": csrf_token,
        },
    )

    assert response.status_code == 303
    conversation_url = response.headers["location"]
    conversation = await client.get(conversation_url)
    assert "apt-get exited 100" in conversation.text
    assert "Unable to fetch" in conversation.text


async def test_explain_update_run_requires_failed_status(client, db_session_factory):
    machine_id = await create_machine(db_session_factory)
    await setup_provider(db_session_factory)
    async with db_session_factory() as db:
        run = MachineUpdateRun(
            machine_id=machine_id,
            strategy=UpgradeStrategy.DIST_UPGRADE,
            status=UpdateRunStatus.SUCCEEDED,
        )
        db.add(run)
        await db.commit()
        run_id = run.id

    await client.get("/ai")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/ai/explain",
        data={
            "kind": "update_run",
            "machine_id": str(machine_id),
            "run_id": str(run_id),
            "csrf_token": csrf_token,
        },
    )

    assert response.status_code == 400


async def test_explain_readiness_findings(client, db_session_factory):
    machine_id = await create_machine(db_session_factory)
    await setup_provider(db_session_factory)
    async with db_session_factory() as db:
        machine = await db.get(Machine, machine_id)
        assert machine is not None
        machine.readiness_missing = ["ncurses-term (needed for full-color terminal output)"]
        await db.commit()

    await client.get("/ai")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/ai/explain",
        data={"kind": "readiness", "machine_id": str(machine_id), "csrf_token": csrf_token},
    )

    assert response.status_code == 303
    conversation = await client.get(response.headers["location"])
    assert "ncurses-term" in conversation.text


async def test_explain_readiness_with_nothing_missing_is_rejected(client, db_session_factory):
    machine_id = await create_machine(db_session_factory)
    await setup_provider(db_session_factory)

    await client.get("/ai")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/ai/explain",
        data={"kind": "readiness", "machine_id": str(machine_id), "csrf_token": csrf_token},
    )

    assert response.status_code == 400


async def test_explain_requires_a_configured_ai_model(client, db_session_factory):
    machine_id = await create_machine(db_session_factory)
    run_id = await _create_failed_run(db_session_factory, machine_id, error="boom")

    await client.get("/ai")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/ai/explain",
        data={
            "kind": "update_run",
            "machine_id": str(machine_id),
            "run_id": str(run_id),
            "csrf_token": csrf_token,
        },
    )

    assert response.status_code == 400


async def test_explain_is_scoped_to_machines_the_account_can_see(
    client, db_session_factory, login_as
):
    machine_id = await create_machine(db_session_factory)
    await setup_provider(db_session_factory)
    run_id = await _create_failed_run(db_session_factory, machine_id, error="boom")

    restricted_perms = ALL_AI_PERMISSIONS | {Permission.GROUP_VIEW}
    await login_as(client, permissions=restricted_perms, group_ids=[uuid.uuid4()])
    await client.get("/ai")
    csrf_token = client.cookies.get("csrftoken")

    response = await client.post(
        "/ai/explain",
        data={
            "kind": "update_run",
            "machine_id": str(machine_id),
            "run_id": str(run_id),
            "csrf_token": csrf_token,
        },
    )

    assert response.status_code == 404


async def test_update_run_page_offers_ask_ai_why_button_when_failed(client, db_session_factory):
    machine_id = await create_machine(db_session_factory)
    await setup_provider(db_session_factory)
    run_id = await _create_failed_run(db_session_factory, machine_id, error="boom")

    response = await client.get(f"/machines/{machine_id}/updates/{run_id}")

    assert 'action="/ai/explain"' in response.text
    assert 'value="update_run"' in response.text


async def test_readiness_banner_offers_ask_ai_why_button(client, db_session_factory):
    """The readiness banner itself lives on the Settings tab (see
    app/web/templates/machines/edit.html) — Overview only shows a short
    mention with a link there."""
    machine_id = await create_machine(db_session_factory)
    async with db_session_factory() as db:
        machine = await db.get(Machine, machine_id)
        assert machine is not None
        machine.readiness_missing = ["ncurses-term (needed for full-color terminal output)"]
        await db.commit()

    response = await client.get(f"/machines/{machine_id}/edit")

    assert 'action="/ai/explain"' in response.text
    assert 'value="readiness"' in response.text
