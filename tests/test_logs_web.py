"""HTTP-level tests for the Logs tab (`GET /machines/{id}/logs`) — real SSH
stays mocked out via the autouse `celery_calls` fixture (see
tests/test_onboarding.py's own module comment for the same pattern), so
these only check dispatch (which task, which arguments) and rendering.
"""

from __future__ import annotations

from app.db.models.role import Permission
from tests.test_onboarding import _make_machine


async def test_logs_tab_defaults_to_the_journal(client, db_session_factory, celery_calls):
    machine_id = await _make_machine(db_session_factory)

    response = await client.get(f"/machines/{machine_id}/logs")

    assert response.status_code == 200
    assert celery_calls.names == ["app.tasks.jobs.view_machine_journal"]
    assert celery_calls[0][2] == {
        "lines": 200,
        "search": "",
        "since": "",
        "until": "",
    }
    assert "fake" in response.text  # the fake task result's default output


async def test_logs_tab_views_a_file_when_path_given(client, db_session_factory, celery_calls):
    machine_id = await _make_machine(db_session_factory)

    response = await client.get(
        f"/machines/{machine_id}/logs", params={"path": "/var/log/syslog", "search": "error"}
    )

    assert response.status_code == 200
    assert celery_calls.names == ["app.tasks.jobs.view_machine_log_file"]
    assert celery_calls[0][2]["path"] == "/var/log/syslog"
    assert celery_calls[0][2]["search"] == "error"


async def test_logs_tab_shows_the_reported_error(client, db_session_factory, celery_calls):
    machine_id = await _make_machine(db_session_factory)
    celery_calls.result_for["app.tasks.jobs.view_machine_journal"] = {
        "ok": False,
        "error": "No pinned host key fingerprint yet.",
    }

    response = await client.get(f"/machines/{machine_id}/logs")

    assert response.status_code == 200
    assert "No pinned host key fingerprint yet." in response.text


async def test_logs_tab_requires_terminal_permission(client, login_as, db_session_factory):
    machine_id = await _make_machine(db_session_factory)
    await login_as(client, permissions={Permission.MACHINE_VIEW})

    response = await client.get(f"/machines/{machine_id}/logs")

    assert response.status_code == 403


async def test_logs_tab_hidden_from_tabnav_without_permission(client, login_as, db_session_factory):
    machine_id = await _make_machine(db_session_factory)
    await login_as(client, permissions={Permission.MACHINE_VIEW})

    response = await client.get(f"/machines/{machine_id}")

    assert response.status_code == 200
    assert f'href="/machines/{machine_id}/logs"' not in response.text
