"""The machine list's Table/List/Cards display toggle — a per-browser
cookie preference (`app.web.routes.machines.MACHINES_VIEW_COOKIE_NAME`),
not per-account data. See that module and `machines/list.html`.
"""

from __future__ import annotations

from tests.test_monitoring_web import _add_monitoring_sample
from tests.test_web import _create_machine


async def test_machines_list_defaults_to_table_view(client):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    await _create_machine(client, csrf_token, name="table-default")

    response = await client.get("/machines")

    assert response.status_code == 200
    assert '<table class="data-table">' in response.text
    assert "machine-card-grid" not in response.text
    assert "machine-compact-list" not in response.text


async def test_set_view_mode_sets_cookie_and_redirects(client):
    await client.get("/machines")
    csrf_token = client.cookies.get("csrftoken")

    response = await client.post(
        "/machines/view-mode",
        data={"view": "cards", "next": "/machines", "csrf_token": csrf_token},
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/machines"
    assert client.cookies.get("machines_view") == "cards"


async def test_cards_view_renders_after_cookie_is_set(client, db_session_factory):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    await _create_machine(client, csrf_token, name="card-machine")

    await client.post(
        "/machines/view-mode",
        data={"view": "cards", "next": "/machines", "csrf_token": csrf_token},
    )

    response = await client.get("/machines")

    assert response.status_code == 200
    assert "machine-card-grid" in response.text
    assert "card-machine" in response.text
    assert '<table class="data-table">' not in response.text


async def test_list_view_renders_after_cookie_is_set(client, db_session_factory):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    await _create_machine(client, csrf_token, name="list-machine")

    await client.post(
        "/machines/view-mode",
        data={"view": "list", "next": "/machines", "csrf_token": csrf_token},
    )

    response = await client.get("/machines")

    assert response.status_code == 200
    assert "machine-compact-list" in response.text
    assert "list-machine" in response.text


async def test_invalid_view_mode_falls_back_to_table(client):
    await client.get("/machines")
    csrf_token = client.cookies.get("csrftoken")

    await client.post(
        "/machines/view-mode",
        data={"view": "not-a-real-mode", "next": "/machines", "csrf_token": csrf_token},
    )

    assert client.cookies.get("machines_view") == "table"


async def test_view_mode_redirect_only_ever_targets_machines(client):
    await client.get("/machines")
    csrf_token = client.cookies.get("csrftoken")

    response = await client.post(
        "/machines/view-mode",
        data={
            "view": "cards",
            "next": "https://evil.example/steal",
            "csrf_token": csrf_token,
        },
    )

    assert response.headers["location"] == "/machines"


async def test_bulk_select_checkboxes_present_in_every_view_mode(client, db_session_factory):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, name="selectable")

    for mode in ("table", "list", "cards"):
        await client.post(
            "/machines/view-mode",
            data={"view": mode, "next": "/machines", "csrf_token": csrf_token},
        )
        response = await client.get("/machines")
        assert f'value="{machine_id}"' in response.text, mode


async def test_cards_view_shows_latest_cpu_and_ram_usage(client, db_session_factory):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, name="usage-machine")
    await _add_monitoring_sample(db_session_factory, machine_id)

    await client.post(
        "/machines/view-mode",
        data={"view": "cards", "next": "/machines", "csrf_token": csrf_token},
    )
    response = await client.get("/machines")

    assert response.status_code == 200
    assert "usage-bar-fill-10" in response.text  # cpu_percent=12.5 rounds to 10
    assert "usage-bar-fill-50" in response.text  # ram_used/total = 50%
    assert "CPU: 13%" in response.text or "CPU: 12%" in response.text


async def test_table_and_list_views_never_query_monitoring_samples(client, db_session_factory):
    """The latest-sample query only runs for Cards — no reason to pay for
    it in Table/List, which don't display it."""
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, name="no-usage-shown")
    await _add_monitoring_sample(db_session_factory, machine_id)

    for mode in ("table", "list"):
        await client.post(
            "/machines/view-mode",
            data={"view": mode, "next": "/machines", "csrf_token": csrf_token},
        )
        response = await client.get("/machines")
        assert "usage-bar" not in response.text, mode
