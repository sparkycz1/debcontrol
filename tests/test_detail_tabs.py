"""The machine/group sub-navigation (Overview / Updates / Terminal / Power /
Settings) — a plain row of links across each one's own pages, current tab
highlighted. See `partials/_tabnav.html`, `machines._machine_tabs`, and
`machine_groups._group_tabs`.
"""

from __future__ import annotations

import re

import httpx

from app.db.models.role import Permission
from tests.test_web import _create_machine, _pin_host_key


def _tabnav_html(page_text: str) -> str:
    """Just the `<nav class="tab-nav">...</nav>` fragment — the site header
    has its own `class="active" aria-current="page"` markup on the
    "Machines"/"Machine groups" nav link, which would otherwise be
    indistinguishable from the tab-nav's own active marker."""
    match = re.search(r'<nav class="tab-nav">.*?</nav>', page_text, re.DOTALL)
    assert match is not None, "no tab-nav found on this page"
    return match.group(0)


async def _create_group(client: httpx.AsyncClient, csrf_token: str, name: str) -> str:
    response = await client.post(
        "/machine-groups", data={"name": name, "description": "", "csrf_token": csrf_token}
    )
    location: str = response.headers["location"]
    return location.rsplit("/", 1)[-1]


async def test_machine_pages_all_show_the_same_tabs(client, db_session_factory):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, name="tabbed")
    await _pin_host_key(db_session_factory, machine_id)

    pages = {
        "overview": f"/machines/{machine_id}",
        "monitoring": f"/machines/{machine_id}/monitoring",
        "updates": f"/machines/{machine_id}/updates",
        "terminal": f"/machines/{machine_id}/terminal",
        "power": f"/machines/{machine_id}/power",
        "settings": f"/machines/{machine_id}/edit",
    }
    for active, url in pages.items():
        response = await client.get(url)
        assert response.status_code == 200, active
        tabnav = _tabnav_html(response.text)
        # Every tab links to every page, and exactly the current one is marked active.
        for other_url in pages.values():
            assert f'href="{other_url}"' in tabnav
        assert tabnav.count('class="active" aria-current="page"') == 1


async def test_terminal_tab_hidden_without_permission(client, login_as, db_session_factory):
    await client.get("/machines/new")
    machine_id = await _create_machine(client, client.cookies.get("csrftoken"), name="noterm")
    await _pin_host_key(db_session_factory, machine_id)

    await login_as(client, permissions={Permission.MACHINE_VIEW})
    response = await client.get(f"/machines/{machine_id}")
    assert response.status_code == 200
    assert f'href="/machines/{machine_id}/terminal"' not in response.text


async def test_machine_updates_tab_has_the_trigger_form_and_history(client, db_session_factory):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, name="updatestab")
    await _pin_host_key(db_session_factory, machine_id)

    response = await client.get(f"/machines/{machine_id}/updates")
    assert response.status_code == 200
    assert f'action="/machines/{machine_id}/updates/preview"' in response.text
    assert f'hx-post="/machines/{machine_id}/check-updates"' in response.text


async def test_machine_power_tab_has_reboot_and_shutdown_links(client, db_session_factory):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, name="powertab")
    await _pin_host_key(db_session_factory, machine_id)

    response = await client.get(f"/machines/{machine_id}/power")
    assert response.status_code == 200
    assert f'href="/machines/{machine_id}/power/reboot"' in response.text
    assert f'href="/machines/{machine_id}/power/shutdown"' in response.text


async def test_machine_settings_tab_has_edit_form_and_delete_button(client, db_session_factory):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, name="settingstab")

    response = await client.get(f"/machines/{machine_id}/edit")
    assert response.status_code == 200
    assert 'name="ip_address"' in response.text
    assert f'action="/machines/{machine_id}/delete"' in response.text


async def test_group_pages_all_show_the_same_tabs(client):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    group_id = await _create_group(client, csrf_token, "tabbedgroup")

    pages = {
        "overview": f"/machine-groups/{group_id}",
        "updates": f"/machine-groups/{group_id}/updates",
        "power": f"/machine-groups/{group_id}/power",
    }
    for active, url in pages.items():
        response = await client.get(url)
        assert response.status_code == 200, active
        tabnav = _tabnav_html(response.text)
        for other_url in pages.values():
            assert f'href="{other_url}"' in tabnav
        assert tabnav.count('class="active" aria-current="page"') == 1


async def test_group_updates_tab_has_both_forms(client):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    group_id = await _create_group(client, csrf_token, "updatesgroup")

    response = await client.get(f"/machine-groups/{group_id}/updates")
    assert response.status_code == 200
    assert f'action="/machine-groups/{group_id}/updates"' in response.text
    assert f'action="/machine-groups/{group_id}/check-updates"' in response.text


async def test_group_power_tab_has_reboot_and_shutdown_links(client):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    group_id = await _create_group(client, csrf_token, "powergrouptab")

    response = await client.get(f"/machine-groups/{group_id}/power")
    assert response.status_code == 200
    assert f'href="/machine-groups/{group_id}/power/reboot"' in response.text
    assert f'href="/machine-groups/{group_id}/power/shutdown"' in response.text
