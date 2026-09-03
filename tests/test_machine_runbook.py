"""A machine's runbook — the `markdown` Jinja filter (app/web/templating.py,
mistune with escape=True), the create/edit forms, the Overview tab render,
the REST API, and the config export/import round-trip.
"""

from __future__ import annotations

import json

from sqlalchemy import select

from app.db.models.machine import Machine
from app.web.templating import markdown_filter
from tests.test_api_v1_extended import _api_token
from tests.test_web import _create_machine


def test_markdown_filter_renders_basic_formatting():
    html = str(markdown_filter("# Title\n\nSome **bold** text."))
    assert "<h1>Title</h1>" in html
    assert "<strong>bold</strong>" in html


def test_markdown_filter_escapes_raw_html():
    html = str(markdown_filter("<script>alert(1)</script>"))
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_markdown_filter_neutralizes_javascript_links():
    html = str(markdown_filter("[click](javascript:alert(1))"))
    assert "javascript:" not in html


def test_markdown_filter_handles_none_and_empty():
    assert str(markdown_filter(None)) == ""
    assert str(markdown_filter("")) == ""


async def test_create_machine_web_form_sets_runbook(client):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(
        client, csrf_token, runbook="# Contact\n\nCall **ops** if this breaks."
    )

    response = await client.get(f"/machines/{machine_id}")
    assert "<h1>Contact</h1>" in response.text
    assert "<strong>ops</strong>" in response.text


async def test_overview_hides_runbook_panel_when_empty(client):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token)

    response = await client.get(f"/machines/{machine_id}")
    assert "Runbook" not in response.text


async def test_edit_machine_web_form_updates_runbook(client, db_session_factory):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token)

    edit_data = {
        "name": "m",
        "ip_address": "10.0.1.1",
        "port": "22",
        "username": "admin",
        "auth_method": "password",
        "runbook": "Reboot fixes everything.",
        "csrf_token": csrf_token,
    }
    response = await client.post(f"/machines/{machine_id}/edit", data=edit_data)
    assert response.status_code == 303

    async with db_session_factory() as db:
        machine = await db.get(Machine, machine_id)
        assert machine is not None
        assert machine.runbook == "Reboot fixes everything."


async def test_machines_api_sets_and_returns_runbook(client):
    headers = await _api_token(client)
    create_resp = await client.post(
        "/api/v1/machines",
        json={
            "name": "api-runbook",
            "ip_address": "10.0.3.1",
            "port": 22,
            "username": "admin",
            "auth_method": "password",
            "secret": "s3cret",
            "runbook": "Escalate to #ops on Slack.",
        },
        headers=headers,
    )
    assert create_resp.status_code == 201, create_resp.text
    assert create_resp.json()["runbook"] == "Escalate to #ops on Slack."

    machine_id = create_resp.json()["id"]
    get_resp = await client.get(f"/api/v1/machines/{machine_id}", headers=headers)
    assert get_resp.json()["runbook"] == "Escalate to #ops on Slack."


async def test_config_export_import_round_trips_runbook(client, db_session_factory):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    await _create_machine(client, csrf_token, name="export-runbook", runbook="Owner: NOC team.")

    export_resp = await client.get("/machines/config/export", params={"format": "json"})
    payload = export_resp.json()
    exported = next(m for m in payload["machines"] if m["name"] == "export-runbook")
    assert exported["runbook"] == "Owner: NOC team."

    reimport_payload = {
        "machines": [{**exported, "name": "reimported-runbook"}],
        "groups": [],
    }
    import_resp = await client.post(
        "/machines/config/import",
        data={"csrf_token": csrf_token, "json_text": json.dumps(reimport_payload)},
    )
    assert import_resp.status_code == 200, import_resp.text

    async with db_session_factory() as db:
        result = await db.execute(select(Machine).where(Machine.name == "reimported-runbook"))
        reimported = result.scalar_one_or_none()
        assert reimported is not None
        assert reimported.runbook == "Owner: NOC team."
