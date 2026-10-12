"""Runbooks (`app.services.runbooks`): written by someone with a shell,
run by someone without one, with parameters that cannot become commands."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx2 import AsyncClient
from sqlalchemy import select

from app.db.models.audit_log import AuditLogEntry
from app.db.models.runbook import Runbook, RunbookRun, RunbookRunStatus
from app.services import runbooks
from app.tasks import jobs
from tests.test_homelab_round import _add_machine
from tests.test_update_history import _api_token

STEPS = "# Stop\nsudo systemctl stop {{unit}}\n\nsudo systemctl start {{unit}}\n"
PARAMS = "unit | Service | nginx.service\n"


def _runbook() -> Runbook:
    data = runbooks.validate(
        "Restart a service", "", runbooks.parse_steps(STEPS), runbooks.parse_params(PARAMS)
    )
    return Runbook(name=data.name, steps=data.steps, params=data.params)


def test_text_form_round_trips() -> None:
    steps, params = runbooks.parse_steps(STEPS), runbooks.parse_params(PARAMS)

    assert steps == [
        {"name": "Stop", "command": "sudo systemctl stop {{unit}}"},
        {"name": "Step 2", "command": "sudo systemctl start {{unit}}"},
    ]
    assert params == [{"key": "unit", "label": "Service", "default": "nginx.service"}]
    assert runbooks.parse_steps(runbooks.steps_as_text(steps)) == steps
    assert runbooks.parse_params(runbooks.params_as_text(params)) == params


def test_values_are_checked_and_quoted() -> None:
    runbook = _runbook()

    default = runbooks.render(runbook, {})
    given = runbooks.render(runbook, {"unit": "php8.3-fpm.service"})

    assert default[0]["command"] == "sudo systemctl stop nginx.service"
    assert given[1]["command"] == "sudo systemctl start php8.3-fpm.service"
    backtick = chr(96)
    for attack in (
        "nginx; rm -rf /",
        "$(reboot)",
        "a b",
        f"x{backtick}id{backtick}",
        "a'b",
        "a\nb",
        "x" * 201,
    ):
        with pytest.raises(runbooks.RunbookError):
            runbooks.render(runbook, {"unit": attack})


@pytest.mark.parametrize(
    ("steps", "params", "message"),
    [
        ("", "", "at least one step"),
        ("echo {{missing}}", "", "not among the parameters"),
        ("echo hi", "Bad Key | x", "a key is lowercase"),
        ("echo hi", "a\na", "listed twice"),
        ("echo hi", "a | A | has space", "not allowed"),
    ],
)
def test_a_runbook_that_cannot_work_is_refused(steps: str, params: str, message: str) -> None:
    with pytest.raises(runbooks.RunbookError, match=message):
        runbooks.validate("x", None, runbooks.parse_steps(steps), runbooks.parse_params(params))


async def test_create_preview_run_and_see_the_result(
    client: AsyncClient, db_session_factory: Any, celery_calls: Any, monkeypatch: Any
) -> None:
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    machine_id = await _add_machine(db_session_factory, name="web1")
    await client.get("/runbooks")
    csrf = client.cookies.get("csrftoken")

    bad = await client.post(
        "/runbooks", data={"csrf_token": csrf, "name": "Broken", "steps": "echo {{nope}}"}
    )
    created = await client.post(
        "/runbooks",
        data={"csrf_token": csrf, "name": "Restart a service", "steps": STEPS, "params": PARAMS},
        follow_redirects=False,
    )
    async with db_session_factory() as db:
        runbook = (await db.execute(select(Runbook))).scalars().one()
    base = f"/runbooks/{runbook.id}"
    target = {"csrf_token": csrf, "target_type": "machine", "machine_id": str(machine_id)}

    listing = await client.get(f"/runbooks?machine_id={machine_id}")
    form = await client.get(f"{base}/run?machine_id={machine_id}")
    refused = await client.post(f"{base}/preview", data={**target, "param_unit": "x; reboot"})
    preview = await client.post(f"{base}/preview", data={**target, "param_unit": "redis.service"})
    started = await client.post(
        f"{base}/run", data={**target, "param_unit": "redis.service"}, follow_redirects=False
    )

    assert bad.status_code == 400 and "not among the parameters" in bad.text
    assert created.status_code == 303
    assert f"{base}/run?machine_id={machine_id}" in listing.text
    assert 'value="nginx.service"' in form.text
    assert refused.status_code == 400 and "no spaces or quotes" in refused.text
    assert "sudo systemctl stop redis.service" in preview.text and "web1" in preview.text
    assert started.status_code == 303
    batch_url = started.headers["location"]
    queued = [c for c in celery_calls if c[0] == "app.tasks.jobs.run_runbook"]
    assert len(queued) == 1

    # The worker's side: the second step fails, and the run says so.
    seen: list[str] = []

    async def fake_run(_machine: Any, _secret: Any, command: str, *_args: Any) -> Any:
        seen.append(command)

        class _Result:
            exit_status = 0 if "stop" in command else 5
            output = "ok" if "stop" in command else "Unit not found."

        return _Result()

    monkeypatch.setattr(jobs, "run_command", fake_run)
    await jobs._run_runbook(queued[0][1][0])
    await jobs._run_runbook(queued[0][1][0])  # a second delivery does nothing
    page = await client.get(batch_url)

    assert seen == ["sudo systemctl stop redis.service", "sudo systemctl start redis.service"]
    assert "exited with status 5" in page.text and "Unit not found." in page.text
    assert "hx-get" not in page.text
    async with db_session_factory() as db:
        run = (await db.execute(select(RunbookRun))).scalars().one()
        actions = list((await db.execute(select(AuditLogEntry.action))).scalars().all())
    assert run.status == RunbookRunStatus.FAILED and run.started_by == "test-admin"
    assert {"runbook.create", "runbook.run"} <= set(actions)


async def test_api_mirrors_the_pages(
    client: AsyncClient, db_session_factory: Any, celery_calls: Any
) -> None:
    machine_id = await _add_machine(db_session_factory, name="api1")
    headers = await _api_token(client)
    body = {
        "name": "Clear cache",
        "steps": [{"name": "Clear", "command": "rm -rf /var/cache/app/{{name}}"}],
        "params": [{"key": "name", "label": "Cache", "default": "tmp"}],
    }

    created = await client.post("/api/v1/runbooks", headers=headers, json=body)
    twice = await client.post("/api/v1/runbooks", headers=headers, json=body)
    runbook_id = created.json()["id"]
    both = await client.post(
        f"/api/v1/runbooks/{runbook_id}/run",
        headers=headers,
        json={"machine_ids": [str(machine_id)], "group_id": str(uuid.uuid4())},
    )
    unsafe = await client.post(
        f"/api/v1/runbooks/{runbook_id}/run",
        headers=headers,
        json={"machine_ids": [str(machine_id)], "values": {"name": "../../etc; id"}},
    )
    started = await client.post(
        f"/api/v1/runbooks/{runbook_id}/run",
        headers=headers,
        json={"machine_ids": [str(machine_id)], "values": {"name": "thumbs"}},
    )
    batch = await client.get(f"/api/v1/runbooks/runs/{started.json()['batch_id']}", headers=headers)
    deleted = await client.delete(f"/api/v1/runbooks/{runbook_id}", headers=headers)

    assert created.status_code == 201 and twice.status_code == 422
    assert both.status_code == 422 and unsafe.status_code == 422
    assert started.json()["started"] == 1
    assert batch.json()["runs"][0]["commands"] == [
        {"name": "Clear", "command": "rm -rf /var/cache/app/thumbs"}
    ]
    assert deleted.status_code == 204
    assert celery_calls.names.count("app.tasks.jobs.run_runbook") == 1
