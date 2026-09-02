"""HTTP-level tests for the `run_command` scheduled action's extra
permission gate — creating/editing a task that uses it needs
`action.terminal` on top of the plain `scheduling.manage` every other
action is satisfied by (see `app.scheduling.actions.ScheduledActionSpec.
extra_permission` and `app.web.routes.scheduling._action_permission_error`).
"""

from __future__ import annotations

from app.db.models.role import Permission


async def test_new_task_form_lists_run_command_for_a_full_permission_user(client):
    response = await client.get("/scheduling/new")

    assert response.status_code == 200
    assert "Run command" in response.text


async def test_new_task_form_hides_run_command_without_terminal_permission(client, login_as):
    await login_as(client, permissions={Permission.SCHEDULING_MANAGE, Permission.MACHINE_VIEW})

    response = await client.get("/scheduling/new")

    assert response.status_code == 200
    assert "Run command" not in response.text


async def test_create_run_command_task_succeeds_with_terminal_permission(client):
    await client.get("/scheduling/new")
    csrf_token = client.cookies.get("csrftoken")

    response = await client.post(
        "/scheduling",
        data={
            "name": "nightly cleanup",
            "target": "all",
            "action": "run_command",
            "param_command": "apt-get clean",
            "cron_expression": "0 3 * * *",
            "is_enabled": "on",
            "csrf_token": csrf_token,
        },
    )

    assert response.status_code == 303
    listing = await client.get("/scheduling")
    assert "nightly cleanup" in listing.text
    assert "Run command" in listing.text


async def test_create_run_command_task_rejected_without_terminal_permission(client, login_as):
    await login_as(client, permissions={Permission.SCHEDULING_MANAGE, Permission.MACHINE_VIEW})
    csrf_token = client.cookies.get("csrftoken")
    if not csrf_token:
        await client.get("/scheduling/new")
        csrf_token = client.cookies.get("csrftoken")

    response = await client.post(
        "/scheduling",
        data={
            "name": "sneaky",
            "target": "all",
            "action": "run_command",
            "param_command": "rm -rf /",
            "cron_expression": "0 3 * * *",
            "is_enabled": "on",
            "csrf_token": csrf_token,
        },
    )

    assert response.status_code == 422
    assert "action.terminal" in response.text
    listing = await client.get("/scheduling")
    assert "sneaky" not in listing.text
