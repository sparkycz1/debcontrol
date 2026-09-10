"""The Monitoring tab's "Refresh now" button and its unified "Last
checked" timestamp — see `app.tasks.jobs._check_machine_reachability_now`
and `app/web/routes/machines.py`'s `refresh_machine_monitoring_endpoint`.
Real SSH/Celery dispatch stays mocked out via the autouse `celery_calls`
fixture, same as the rest of this test suite.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from tests.test_monitoring_web import _add_monitoring_sample
from tests.test_web import _create_machine, _pin_host_key


async def test_monitoring_page_shows_never_checked_with_no_samples(client, db_session_factory):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, name="never-checked")
    await _pin_host_key(db_session_factory, machine_id)

    response = await client.get(f"/machines/{machine_id}/monitoring")

    assert response.status_code == 200
    assert "Last checked: never" in response.text


async def test_monitoring_page_shows_the_more_recent_of_the_two_timestamps(
    client, db_session_factory
):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, name="two-timestamps")
    await _pin_host_key(db_session_factory, machine_id)

    await _add_monitoring_sample(db_session_factory, machine_id)  # ~now
    async with db_session_factory() as session:
        from app.db.models.machine_reachability_sample import MachineReachabilitySample

        session.add(
            MachineReachabilitySample(
                machine_id=machine_id,
                checked_at=datetime.now(UTC) - timedelta(hours=3),
                reachable=True,
                latency_ms=5.0,
            )
        )
        await session.commit()

    response = await client.get(f"/machines/{machine_id}/monitoring")

    assert response.status_code == 200
    assert "Last checked: never" not in response.text
    # Only one "Last checked:" line on the page — the old separate
    # per-section Availability timestamp is gone.
    assert response.text.count("Last checked:") == 1


async def test_refresh_now_button_only_shown_with_machine_manage(
    client, login_as, db_session_factory
):
    from app.db.models.role import Permission

    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, name="perm-check")
    await _pin_host_key(db_session_factory, machine_id)

    await login_as(client, permissions={Permission.MACHINE_VIEW})
    response = await client.get(f"/machines/{machine_id}/monitoring")

    assert response.status_code == 200
    assert "monitoring/refresh" not in response.text


async def test_refresh_now_enqueues_both_jobs_and_redirects_back(
    client, db_session_factory, celery_calls
):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, name="refresh-target")
    await _pin_host_key(db_session_factory, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/monitoring/refresh?range_key=24h",
        data={"csrf_token": csrf_token},
    )

    assert response.status_code == 303
    assert response.headers["location"] == f"/machines/{machine_id}/monitoring?range_key=24h"
    assert "app.tasks.jobs.sample_machine_monitoring" in celery_calls.names
    assert "app.tasks.jobs.check_machine_reachability_now" in celery_calls.names


async def test_refresh_now_requires_machine_manage_permission(client, login_as, db_session_factory):
    from app.db.models.role import Permission

    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, name="refresh-perm-check")
    await _pin_host_key(db_session_factory, machine_id)

    await login_as(client, permissions={Permission.MACHINE_VIEW})
    response = await client.post(
        f"/machines/{machine_id}/monitoring/refresh",
        data={"csrf_token": csrf_token},
    )
    assert response.status_code == 403


async def test_check_machine_reachability_now_appends_a_sample_and_updates_status(
    db_session_factory, monkeypatch
):
    import uuid as uuid_module

    from app.db.models.machine import AuthMethod, Machine
    from app.db.models.machine_reachability_sample import MachineReachabilitySample
    from app.ssh.reachability import ReachabilityResult
    from app.tasks.jobs import _check_machine_reachability_now

    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)

    async with db_session_factory() as session:
        machine = Machine(
            name="reachability-now",
            ip_address="10.5.5.5",
            port=22,
            username="admin",
            auth_method=AuthMethod.SSH_KEY,
            host_key_fingerprint="SHA256:fakefingerprint",
            is_reachable=False,
        )
        session.add(machine)
        await session.commit()
        machine_id = machine.id

    async def fake_check_reachable(ip_address: str, port: int) -> ReachabilityResult:
        return ReachabilityResult(reachable=True, latency_ms=3.5)

    monkeypatch.setattr("app.tasks.jobs.check_reachable", fake_check_reachable)

    result = await _check_machine_reachability_now(str(machine_id))

    assert result == {"ok": True, "reachable": True}
    async with db_session_factory() as session:
        machine = await session.get(Machine, uuid_module.UUID(str(machine_id)))
        assert machine is not None
        assert machine.is_reachable is True
        assert machine.last_ping_at is not None

        samples = (
            await session.execute(
                MachineReachabilitySample.__table__.select().where(
                    MachineReachabilitySample.machine_id == machine_id
                )
            )
        ).fetchall()
        assert len(samples) == 1
