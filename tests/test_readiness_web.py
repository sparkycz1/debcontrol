"""HTTP-level tests for the post-onboarding readiness check — the
Overview-tab banner, "Re-check", and the "fix an already-onboarded
machine" one-time-credential flow. Real SSH stays mocked out via the
autouse `celery_calls` fixture (see tests/test_onboarding.py's own module
comment for the same pattern).
"""

from __future__ import annotations

from app.db.models.machine import AuthMethod, Machine
from tests.test_onboarding import _make_machine
from tests.test_web import _create_machine


async def test_trust_host_key_dispatches_facts_and_readiness(
    client, db_session_factory, celery_calls
):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, name="fresh-trust")

    response = await client.post(
        f"/machines/{machine_id}/trust-host-key",
        data={"fingerprint": "SHA256:" + "a" * 43, "csrf_token": csrf_token},
    )
    assert response.status_code in (200, 303)
    assert "app.tasks.jobs.refresh_machine_facts" in celery_calls.names
    assert "app.tasks.jobs.check_machine_readiness" in celery_calls.names


async def test_overview_shows_no_banner_when_readiness_ok(client, db_session_factory):
    machine_id = await _make_machine(db_session_factory)

    response = await client.get(f"/machines/{machine_id}")

    assert response.status_code == 200
    assert "recheck-readiness" not in response.text


async def test_overview_shows_banner_when_readiness_missing(client, db_session_factory):
    machine_id = await _make_machine(db_session_factory)
    async with db_session_factory() as session:
        machine = await session.get(Machine, machine_id)
        assert machine is not None
        machine.readiness_missing = ["ncurses-term (needed for full-color terminal output)"]
        await session.commit()

    response = await client.get(f"/machines/{machine_id}")

    assert response.status_code == 200
    assert "ncurses-term" in response.text
    assert f'action="/machines/{machine_id}/recheck-readiness"' in response.text


async def test_overview_banner_offers_credential_form_for_ssh_key_machines(
    client, db_session_factory
):
    machine_id = await _make_machine(db_session_factory)  # PASSWORD auth by default
    async with db_session_factory() as session:
        machine = await session.get(Machine, machine_id)
        assert machine is not None
        machine.auth_method = AuthMethod.SSH_KEY
        machine.readiness_missing = [
            "passwordless sudo for dmidecode (needed for the RAM speed fact)"
        ]
        await session.commit()

    response = await client.get(f"/machines/{machine_id}")

    assert response.status_code == 200
    assert f'action="/machines/{machine_id}/run-onboarding-with-credential"' in response.text
    assert 'name="password"' in response.text


async def test_recheck_readiness_dispatches_the_task(client, db_session_factory, celery_calls):
    machine_id = await _make_machine(db_session_factory)

    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        f"/machines/{machine_id}/recheck-readiness", data={"csrf_token": csrf_token}
    )

    assert response.status_code in (200, 303)
    assert "app.tasks.jobs.check_machine_readiness" in celery_calls.names


async def test_run_onboarding_with_credential_success_leaves_the_task_to_finish(
    client, db_session_factory, celery_calls
):
    machine_id = await _make_machine(db_session_factory)
    async with db_session_factory() as session:
        machine = await session.get(Machine, machine_id)
        assert machine is not None
        machine.auth_method = AuthMethod.SSH_KEY
        await session.commit()

    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        f"/machines/{machine_id}/run-onboarding-with-credential",
        data={"username": "root", "password": "hunter2", "csrf_token": csrf_token},
    )

    assert response.status_code in (200, 303)
    assert celery_calls.names == [
        "app.tasks.jobs.run_machine_onboarding",
        "app.tasks.jobs.check_machine_readiness",
    ]


async def test_run_onboarding_with_credential_failure_restores_previous_auth(
    client, db_session_factory, celery_calls
):
    machine_id = await _make_machine(db_session_factory)
    async with db_session_factory() as session:
        machine = await session.get(Machine, machine_id)
        assert machine is not None
        machine.auth_method = AuthMethod.SSH_KEY
        machine.username = "debcontrol"
        await session.commit()

    celery_calls.result_for["app.tasks.jobs.run_machine_onboarding"] = {
        "ok": False,
        "error": "Permission denied.",
    }

    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    await client.post(
        f"/machines/{machine_id}/run-onboarding-with-credential",
        data={"username": "root", "password": "hunter2", "csrf_token": csrf_token},
    )

    async with db_session_factory() as session:
        machine = await session.get(Machine, machine_id)
        assert machine is not None
        # Restored to what it was before this one-time attempt — never
        # left sitting on PASSWORD auth with a real credential stored.
        assert machine.auth_method == AuthMethod.SSH_KEY
        assert machine.username == "debcontrol"
        assert machine.secret_encrypted is None
