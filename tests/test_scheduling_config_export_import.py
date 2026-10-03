"""Export/import of scheduled-task configuration — see
`app/services/scheduling_config.py` for the design (name-based target
resolution, the unresolved-target/unknown-action skip policy) and
`app/web/routes/scheduling.py` / `app/web/routes/api_v1_scheduling.py` for
the web/API routes.
"""

from __future__ import annotations

import json
import re

from httpx2 import AsyncClient

from tests.test_web import _create_machine


async def _api_token(client: AsyncClient) -> dict[str, str]:
    await client.get("/account")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/account/api-tokens", data={"name": "scheduling-config-test", "csrf_token": csrf_token}
    )
    match = re.search(r"<textarea readonly rows=\"2\">([^<]+)</textarea>", response.text)
    assert match is not None
    return {"Authorization": f"Bearer {match.group(1)}"}


async def test_export_resolves_machine_target_to_name(client):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, name="sched-target")

    await client.post(
        "/scheduling",
        data={
            "name": "exported-task",
            "target": f"machine:{machine_id}",
            "action": "check_updates",
            "cron_expression": "0 3 * * *",
            "is_enabled": "on",
            "csrf_token": csrf_token,
        },
    )

    response = await client.get("/scheduling/config/export")
    assert response.status_code == 200
    data = response.json()
    task = next(t for t in data["scheduled_tasks"] if t["name"] == "exported-task")
    assert task["target_type"] == "machine"
    assert task["target_machine"] == "sched-target"
    assert task["target_group"] is None
    assert task["action"] == "check_updates"


async def test_import_creates_task_for_all_machines(client):
    await client.get("/scheduling/config/import")
    csrf_token = client.cookies.get("csrftoken")
    payload = {
        "scheduled_tasks": [
            {
                "name": "imported-nightly",
                "action": "check_updates",
                "action_params": {},
                "target_type": "all_machines",
                "cron_expression": "0 3 * * *",
                "is_enabled": True,
            }
        ]
    }
    response = await client.post(
        "/scheduling/config/import",
        data={"json_text": json.dumps(payload), "csrf_token": csrf_token},
    )
    assert response.status_code == 200
    assert "Created 1 scheduled task." in response.text

    listing = await client.get("/scheduling")
    assert "imported-nightly" in listing.text


async def test_import_resolves_machine_target_by_name(client):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    await _create_machine(client, csrf_token, name="import-target")

    payload = {
        "scheduled_tasks": [
            {
                "name": "task-for-import-target",
                "action": "check_updates",
                "action_params": {},
                "target_type": "machine",
                "target_machine": "import-target",
                "cron_expression": "0 3 * * *",
                "is_enabled": True,
            }
        ]
    }
    response = await client.post(
        "/scheduling/config/import",
        data={"json_text": json.dumps(payload), "csrf_token": csrf_token},
    )
    assert response.status_code == 200
    assert "Created 1 scheduled task." in response.text

    listing = await client.get("/scheduling")
    assert "task-for-import-target" in listing.text
    assert "import-target" in listing.text


async def test_import_skips_task_with_unknown_machine_name(client):
    await client.get("/scheduling/config/import")
    csrf_token = client.cookies.get("csrftoken")
    payload = {
        "scheduled_tasks": [
            {
                "name": "orphan-task",
                "action": "check_updates",
                "action_params": {},
                "target_type": "machine",
                "target_machine": "does-not-exist",
                "cron_expression": "0 3 * * *",
                "is_enabled": True,
            }
        ]
    }
    response = await client.post(
        "/scheduling/config/import",
        data={"json_text": json.dumps(payload), "csrf_token": csrf_token},
    )
    assert response.status_code == 200
    assert "Skipped 1" in response.text
    assert "No machine named" in response.text

    listing = await client.get("/scheduling")
    assert "orphan-task" not in listing.text


async def test_import_skips_task_with_unknown_action(client):
    await client.get("/scheduling/config/import")
    csrf_token = client.cookies.get("csrftoken")
    payload = {
        "scheduled_tasks": [
            {
                "name": "future-action-task",
                "action": "some_future_action",
                "action_params": {},
                "target_type": "all_machines",
                "cron_expression": "0 3 * * *",
                "is_enabled": True,
            }
        ]
    }
    response = await client.post(
        "/scheduling/config/import",
        data={"json_text": json.dumps(payload), "csrf_token": csrf_token},
    )
    assert response.status_code == 200
    assert "Unknown action" in response.text


async def test_import_respects_restricted_account_scope(client, login_as):
    import uuid

    from app.db.models.role import Permission

    # A restricted account is scoped to a specific machine group — "All
    # machines" is refused outright for one, same as the manual create form
    # (see app.scheduling.targets.target_within_scope).
    await client.get("/machine-groups/new")
    group_resp = await client.post(
        "/machine-groups",
        data={
            "name": "scope-test-group",
            "description": "",
            "csrf_token": client.cookies.get("csrftoken"),
        },
    )
    group_id = uuid.UUID(group_resp.headers["location"].rsplit("/", 1)[-1])

    await login_as(
        client,
        permissions={Permission.SCHEDULING_MANAGE, Permission.SCHEDULING_VIEW},
        group_ids={group_id},
    )
    await client.get("/scheduling/config/import")
    csrf_token = client.cookies.get("csrftoken")
    payload = {
        "scheduled_tasks": [
            {
                "name": "out-of-scope-task",
                "action": "check_updates",
                "action_params": {},
                "target_type": "all_machines",
                "cron_expression": "0 3 * * *",
                "is_enabled": True,
            }
        ]
    }
    response = await client.post(
        "/scheduling/config/import",
        data={"json_text": json.dumps(payload), "csrf_token": csrf_token},
    )
    assert response.status_code == 200
    assert "Skipped 1" in response.text


async def test_import_requires_scheduling_manage_permission(client, login_as):
    from app.db.models.role import Permission

    await login_as(client, permissions={Permission.SCHEDULING_VIEW})
    await client.get("/scheduling/config/import")
    csrf_token = client.cookies.get("csrftoken")
    payload: dict[str, list[object]] = {"scheduled_tasks": []}
    response = await client.post(
        "/scheduling/config/import",
        data={"json_text": json.dumps(payload), "csrf_token": csrf_token},
    )
    assert response.status_code == 403


async def test_api_export_and_import_round_trip(client):
    headers = await _api_token(client)
    await client.get("/scheduling/config/import")
    csrf_token = client.cookies.get("csrftoken")
    await client.post(
        "/scheduling",
        data={
            "name": "api-round-trip",
            "target": "all",
            "action": "check_updates",
            "cron_expression": "0 3 * * *",
            "is_enabled": "on",
            "csrf_token": csrf_token,
        },
    )

    export_response = await client.get("/api/v1/scheduling/config/export", headers=headers)
    assert export_response.status_code == 200
    exported = export_response.json()
    assert any(t["name"] == "api-round-trip" for t in exported["scheduled_tasks"])

    import_response = await client.post(
        "/api/v1/scheduling/config/import", json=exported, headers=headers
    )
    assert import_response.status_code == 200
    result = import_response.json()
    assert "api-round-trip" in result["created_tasks"]
