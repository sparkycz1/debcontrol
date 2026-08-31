"""The Overview/Updates tabs' self-polling fragments — a periodic background
sweep (reachability, facts, packages, update checks; see Celery Beat in
app/tasks/celery_app.py) writes to the DB without any request from an open
browser tab, so the fragment those tabs show has to re-fetch itself on a
timer rather than only ever refreshing on an explicit button click. See the
module comment above `machine_status_panel` in app/web/routes/machines.py.
"""

from __future__ import annotations

from tests.test_web import _create_machine, _pin_host_key


async def test_detail_page_facts_panel_polls_itself(client, db_session_factory):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, name="pollfacts")
    await _pin_host_key(db_session_factory, machine_id)

    response = await client.get(f"/machines/{machine_id}")
    assert response.status_code == 200
    assert f'hx-get="/machines/{machine_id}/facts-panel"' in response.text
    assert 'hx-trigger="every 20s"' in response.text


async def test_facts_panel_endpoint_returns_current_facts(client, db_session_factory):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, name="factspanel")
    await _pin_host_key(db_session_factory, machine_id)

    response = await client.get(f"/machines/{machine_id}/facts-panel")
    assert response.status_code == 200
    assert "Facts" in response.text
    # Not wrapped in its own #facts-panel div — the poll response is swapped
    # into the *existing* section on the page (innerHTML), so re-including
    # the id here would nest a duplicate on every tick.
    assert 'id="facts-panel"' not in response.text


async def test_status_panel_endpoint_reflects_reachability(client, db_session_factory):
    from app.db.models.machine import Machine

    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, name="statuspanel")

    async with db_session_factory() as session:
        machine = await session.get(Machine, machine_id)
        assert machine is not None
        machine.is_reachable = True
        await session.commit()

    response = await client.get(f"/machines/{machine_id}/status-panel")
    assert response.status_code == 200
    assert "online" in response.text
    assert f'hx-get="/machines/{machine_id}/status-panel"' in response.text


async def test_packages_summary_polls_and_its_panel_endpoint_matches(client, db_session_factory):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, name="pollpkgs")
    await _pin_host_key(db_session_factory, machine_id)

    detail = await client.get(f"/machines/{machine_id}")
    assert f'hx-get="/machines/{machine_id}/packages-summary-panel"' in detail.text

    panel = await client.get(f"/machines/{machine_id}/packages-summary-panel")
    assert panel.status_code == 200
    assert "Installed packages" in panel.text
    assert 'id="packages-summary"' not in panel.text

    # The modal's own out-of-band refresh must be unaffected by adding the
    # `poll` flag elsewhere — it still gets no polling attributes.
    modal = await client.get(f"/machines/{machine_id}/packages")
    assert "hx-trigger=\"every" not in modal.text


async def test_update_availability_polls_and_its_panel_endpoint_matches(
    client, db_session_factory
):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, name="pollupdates")
    await _pin_host_key(db_session_factory, machine_id)

    updates_page = await client.get(f"/machines/{machine_id}/updates")
    assert f'hx-get="/machines/{machine_id}/update-availability-panel"' in updates_page.text
    assert 'hx-trigger="every 30s"' in updates_page.text

    panel = await client.get(f"/machines/{machine_id}/update-availability-panel")
    assert panel.status_code == 200
    assert "Not checked yet" in panel.text
    assert 'id="update-availability"' not in panel.text
