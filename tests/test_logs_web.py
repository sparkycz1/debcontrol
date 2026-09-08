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


async def test_logs_browse_defaults_to_the_first_allowed_path(
    client, db_session_factory, celery_calls
):
    machine_id = await _make_machine(db_session_factory)

    response = await client.get(f"/machines/{machine_id}/logs/browse")

    assert response.status_code == 200
    assert celery_calls.names == ["app.tasks.jobs.browse_machine_log_directory"]
    assert celery_calls[0][2]["path"] == "/var/log"
    assert "/var/log" in response.text


async def test_logs_browse_lists_dirs_and_files_as_links(
    client, db_session_factory, celery_calls
):
    machine_id = await _make_machine(db_session_factory)
    celery_calls.result_for["app.tasks.jobs.browse_machine_log_directory"] = {
        "ok": True,
        "entries": [{"name": "syslog", "is_dir": False}, {"name": "nginx", "is_dir": True}],
    }

    response = await client.get(f"/machines/{machine_id}/logs/browse")

    assert response.status_code == 200
    assert f'href="/machines/{machine_id}/logs/browse?path=/var/log/nginx"' in response.text
    assert f'href="/machines/{machine_id}/logs?path=/var/log/syslog"' in response.text


async def test_logs_browse_navigates_into_a_subdirectory(
    client, db_session_factory, celery_calls
):
    machine_id = await _make_machine(db_session_factory)

    response = await client.get(
        f"/machines/{machine_id}/logs/browse", params={"path": "/var/log/nginx"}
    )

    assert response.status_code == 200
    assert celery_calls[0][2]["path"] == "/var/log/nginx"
    # A parent-directory link is offered, but never above the allowed root.
    assert 'path=/var/log"' in response.text


async def test_logs_browse_offers_no_parent_link_at_the_allowed_root(
    client, db_session_factory, celery_calls
):
    machine_id = await _make_machine(db_session_factory)

    response = await client.get(
        f"/machines/{machine_id}/logs/browse", params={"path": "/var/log"}
    )

    assert response.status_code == 200
    # No ".." entry at all — going up from the allowed root itself would
    # only ever fail server-side (app.ssh.logs.is_path_allowed), so it's
    # never offered as a link in the first place.
    assert ">.. (" not in response.text


async def test_logs_browse_shows_the_reported_error(client, db_session_factory, celery_calls):
    machine_id = await _make_machine(db_session_factory)
    celery_calls.result_for["app.tasks.jobs.browse_machine_log_directory"] = {
        "ok": False,
        "error": '"/etc" is outside the allowed log paths.',
    }

    response = await client.get(
        f"/machines/{machine_id}/logs/browse", params={"path": "/etc"}
    )

    assert response.status_code == 200
    assert "outside the allowed log paths" in response.text


async def test_logs_browse_requires_terminal_permission(client, login_as, db_session_factory):
    machine_id = await _make_machine(db_session_factory)
    await login_as(client, permissions={Permission.MACHINE_VIEW})

    response = await client.get(f"/machines/{machine_id}/logs/browse")

    assert response.status_code == 403
