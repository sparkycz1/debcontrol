from __future__ import annotations

from app.db.models.machine_update_run import UpgradeStrategy
from app.db.models.role import Permission
from app.main import app as fastapi_app
from app.ssh.updates import (
    build_update_preview_command,
    parse_apt_simulated_changes,
)
from tests.conftest import FakeArqJob
from tests.test_web import _create_machine, _pin_host_key

# --- Pure parsing/command-building functions (no I/O) ---


def test_build_update_preview_command_uses_simulate_flag():
    command = build_update_preview_command(UpgradeStrategy.DIST_UPGRADE)

    assert "apt-get update -q" in command
    assert " -s dist-upgrade" in command
    assert " -s autoremove" in command
    assert "full-upgrade" not in command
    # Simulate mode never installs/removes anything — autoclean has nothing
    # meaningful to preview (it only deletes already-downloaded .deb files).
    assert "autoclean" not in command


def test_build_update_preview_command_full_upgrade():
    command = build_update_preview_command(UpgradeStrategy.FULL_UPGRADE)

    assert " -s full-upgrade" in command
    assert "dist-upgrade" not in command


def test_parse_apt_simulated_changes_separates_installs_and_removals():
    raw = (
        "Inst libfoo [1.0-1] (1.1-1 Debian:12.5/stable [amd64])\n"
        "Inst libbrandnew (2.0-1 Debian:12.5/stable [amd64])\n"
        "Remv libbaz [1.0-1]\n"
        "Remv libqux [2.0-1]\n"
    )

    installed_or_upgraded, removed = parse_apt_simulated_changes(raw)

    assert [p["name"] for p in installed_or_upgraded] == ["libfoo", "libbrandnew"]
    assert installed_or_upgraded[0]["current_version"] == "1.0-1"
    assert installed_or_upgraded[0]["new_version"] == "1.1-1"
    assert installed_or_upgraded[1]["current_version"] is None
    assert installed_or_upgraded[1]["new_version"] == "2.0-1"

    assert [p["name"] for p in removed] == ["libbaz", "libqux"]
    assert removed[0]["current_version"] == "1.0-1"
    assert removed[0]["new_version"] is None


def test_parse_apt_simulated_changes_handles_empty_output():
    installed_or_upgraded, removed = parse_apt_simulated_changes("")

    assert installed_or_upgraded == []
    assert removed == []


def test_parse_apt_simulated_changes_ignores_unrelated_lines():
    raw = "Reading package lists...\nBuilding dependency tree...\nInst libfoo (1.0-1 stable)\n"

    installed_or_upgraded, removed = parse_apt_simulated_changes(raw)

    assert len(installed_or_upgraded) == 1
    assert removed == []


# --- The preview route ---


async def test_preview_route_requires_action_updates_permission(
    client, login_as, db_session_factory
):
    await client.get("/machines/new")
    machine_id = await _create_machine(client, client.cookies.get("csrftoken"))
    await _pin_host_key(db_session_factory, machine_id)

    await login_as(client, permissions={Permission.MACHINE_VIEW})
    response = await client.get(f"/machines/{machine_id}/updates/preview")
    assert response.status_code == 403


async def test_preview_route_refuses_without_pinned_fingerprint(client):
    await client.get("/machines/new")
    machine_id = await _create_machine(client, client.cookies.get("csrftoken"))

    response = await client.get(f"/machines/{machine_id}/updates/preview")
    assert response.status_code == 400


async def test_preview_route_shows_simulated_plan(client, db_session_factory, monkeypatch):
    await client.get("/machines/new")
    machine_id = await _create_machine(client, client.cookies.get("csrftoken"))
    await _pin_host_key(db_session_factory, machine_id)

    async def _fake_enqueue_job(function, *args, **kwargs):
        assert function == "preview_machine_update"
        return FakeArqJob(
            result={
                "ok": True,
                "to_install_or_upgrade": [
                    {"name": "libfoo", "current_version": "1.0", "new_version": "1.1"}
                ],
                "to_remove": [
                    {"name": "old-kernel-headers", "current_version": "5.10", "new_version": None}
                ],
            }
        )

    monkeypatch.setattr(fastapi_app.state.arq_redis, "enqueue_job", _fake_enqueue_job)

    response = await client.get(f"/machines/{machine_id}/updates/preview")
    assert response.status_code == 200
    assert "old-kernel-headers" in response.text
    assert "libfoo" in response.text
    assert "Confirm" in response.text


async def test_preview_route_surfaces_simulate_failure(client, db_session_factory, monkeypatch):
    await client.get("/machines/new")
    machine_id = await _create_machine(client, client.cookies.get("csrftoken"))
    await _pin_host_key(db_session_factory, machine_id)

    async def _fake_enqueue_job(function, *args, **kwargs):
        return FakeArqJob(result={"ok": False, "error": "machine unreachable"})

    monkeypatch.setattr(fastapi_app.state.arq_redis, "enqueue_job", _fake_enqueue_job)

    response = await client.get(f"/machines/{machine_id}/updates/preview")
    assert response.status_code == 200
    assert "machine unreachable" in response.text


# --- The actual trigger is unaffected: same permission, same pinned-key check ---


async def test_trigger_still_requires_action_updates_permission(
    client, login_as, db_session_factory
):
    await client.get("/machines/new")
    machine_id = await _create_machine(client, client.cookies.get("csrftoken"))
    await _pin_host_key(db_session_factory, machine_id)
    csrf_token = client.cookies.get("csrftoken")

    await login_as(client, permissions={Permission.MACHINE_VIEW})
    response = await client.post(
        f"/machines/{machine_id}/updates",
        data={"strategy": "dist_upgrade", "csrf_token": csrf_token},
    )
    assert response.status_code == 403
