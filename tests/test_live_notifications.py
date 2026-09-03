"""The server-side half of the browser-notification layer on top of
live-updates.js: each machine-scoped page's `[data-live-machine-id]`
anchor also carries the machine's name, so the injected notification
toggle (pure client-side — see static/js/live-updates.js, no dedicated
test here, same as this project's other data-attribute-driven scripts
like monitoring-chart.js) can build a readable notification title
without a second round trip.
"""

from __future__ import annotations

from tests.test_web import _create_machine, _pin_host_key


async def test_overview_tab_carries_the_machine_name_for_notifications(
    client, db_session_factory
):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, name="notify-me")
    await _pin_host_key(db_session_factory, machine_id)

    response = await client.get(f"/machines/{machine_id}")

    assert f'data-live-machine-id="{machine_id}"' in response.text
    assert 'data-live-machine-name="notify-me"' in response.text


async def test_monitoring_tab_carries_the_machine_name_for_notifications(
    client, db_session_factory
):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, name="notify-mon")
    await _pin_host_key(db_session_factory, machine_id)

    response = await client.get(f"/machines/{machine_id}/monitoring")

    assert 'data-live-machine-name="notify-mon"' in response.text


async def test_updates_tab_carries_the_machine_name_for_notifications(
    client, db_session_factory
):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, name="notify-upd")
    await _pin_host_key(db_session_factory, machine_id)

    response = await client.get(f"/machines/{machine_id}/updates")

    assert 'data-live-machine-name="notify-upd"' in response.text
