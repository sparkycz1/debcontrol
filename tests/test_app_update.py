"""Updating debcontrol from Settings -> Update: the app's side
(`app.services.app_update`, the Settings tab, the REST API) and the host
watcher (`scripts/self_update.py`)."""

from __future__ import annotations

import json
import os
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from httpx2 import AsyncClient
from sqlalchemy import select

from app.core.version import APP_VERSION
from app.db.models.audit_log import AuditLogEntry
from app.db.models.role import Permission
from app.services import app_update
from scripts import self_update
from tests.test_api_v1_extended import _api_token


@pytest.fixture
def update_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    (tmp_path / "request").mkdir()
    (tmp_path / "status").mkdir()
    monkeypatch.setattr(app_update, "BASE_DIR", tmp_path)
    return tmp_path


def _install(base: Path) -> None:
    (base / "status" / "watcher.json").write_text(
        json.dumps({"installed_at": "2026-10-17T08:00:00+00:00", "user": "deploy"})
    )


def _available(base: Path, **overrides: object) -> None:
    data: dict[str, object] = {
        "checking": False,
        "checked_at": "2026-10-17T08:00:00+00:00",
        "ok": True,
        "branch": "main",
        "local_version": APP_VERSION,
        "remote_version": "9.9.9",
        "remote_commit": "a" * 40,
        "behind": 3,
        "commits": [{"commit": "abc1234", "subject": "Something new (9.9.9)"}],
        "dirty": False,
    }
    data.update(overrides)
    (base / "status" / "available.json").write_text(json.dumps(data))


# --- app.services.app_update ------------------------------------------------


def test_status_without_watcher(update_dir: Path) -> None:
    status = app_update.read_status()
    assert not status.installed
    assert status.available is None and status.upgrade is None
    assert not status.busy
    with pytest.raises(app_update.WatcherNotInstalledError):
        app_update.request(app_update.CHECK)
    assert not (update_dir / "request" / "check").exists()


def test_status_ignores_garbage(update_dir: Path) -> None:
    _install(update_dir)
    (update_dir / "status" / "available.json").write_text("[1, 2")
    (update_dir / "status" / "upgrade.json").write_text(json.dumps({"state": "rm -rf"}))
    status = app_update.read_status()
    assert status.installed
    assert status.available is None
    assert status.upgrade is None


def test_status_parses_available_upgrade_and_log(update_dir: Path) -> None:
    _install(update_dir)
    _available(update_dir, behind="3", commits="nope")
    (update_dir / "status" / "upgrade.json").write_text(
        json.dumps(
            {
                "state": "failed",
                "started_at": "2026-10-17T08:00:00+00:00",
                "finished_at": "2026-10-17T08:03:00+00:00",
                "exit_code": 1,
                "from_version": "0.116.0",
            }
        )
    )
    (update_dir / "status" / "upgrade.log").write_text(
        "==> Building\x1b[0m\nstep 1\rstep 2\nerror: boom\n"
    )
    status = app_update.read_status()
    assert status.available is not None
    # A wrong type is "nothing known", not an error.
    assert status.available.behind == 0 and status.available.commits == ()
    assert status.upgrade is not None and status.upgrade.state == "failed"
    assert status.upgrade.exit_code == 1
    assert "\x1b" not in status.log_tail
    assert "step 2" in status.log_tail and "step 1" not in status.log_tail
    assert status.as_dict()["last_upgrade"]["state"] == "failed"  # type: ignore[index]


def test_request_writes_trigger_and_refuses_second_upgrade(update_dir: Path) -> None:
    _install(update_dir)
    app_update.request(app_update.UPGRADE)
    assert (update_dir / "request" / "upgrade").read_bytes() == b""
    status = app_update.read_status()
    assert status.pending == ("upgrade",) and status.busy
    with pytest.raises(app_update.UpgradeInProgressError):
        app_update.request(app_update.UPGRADE)
    # A check may still be queued alongside.
    app_update.request(app_update.CHECK)
    with pytest.raises(ValueError):
        app_update.request("../../etc/passwd")


def test_stale_request_is_flagged(update_dir: Path) -> None:
    _install(update_dir)
    app_update.request(app_update.CHECK)
    old = (datetime.now(UTC) - timedelta(minutes=10)).timestamp()
    os.utime(update_dir / "request" / "check", (old, old))
    assert app_update.read_status().pending_stale


# --- Settings -> Update ----------------------------------------------------


async def test_tab_explains_installation_when_watcher_missing(
    client: AsyncClient, update_dir: Path
) -> None:
    response = await client.get("/settings?tab=update")
    assert response.status_code == 200
    assert "install_update_watcher.sh" in response.text
    assert 'action="/settings/update/check"' not in response.text


async def test_tab_offers_the_update(client: AsyncClient, update_dir: Path) -> None:
    _install(update_dir)
    _available(update_dir)
    response = await client.get("/settings?tab=update")
    assert response.status_code == 200
    assert "Version 9.9.9 is available" in response.text
    assert "Something new (9.9.9)" in response.text
    assert 'action="/settings/update/upgrade"' in response.text
    assert "data-confirm=" in response.text


async def test_tab_up_to_date_has_no_upgrade_button(client: AsyncClient, update_dir: Path) -> None:
    _install(update_dir)
    _available(update_dir, behind=0, commits=[], remote_version=APP_VERSION)
    response = await client.get("/settings?tab=update")
    assert "Up to date" in response.text
    assert 'action="/settings/update/upgrade"' not in response.text


async def test_check_and_upgrade_buttons_request_and_audit(
    client: AsyncClient, update_dir: Path, db_session_factory: Any
) -> None:
    _install(update_dir)
    _available(update_dir)
    await client.get("/settings?tab=update")
    csrf_token = client.cookies.get("csrftoken")

    response = await client.post(
        "/settings/update/check", data={"csrf_token": csrf_token}, follow_redirects=False
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/settings?tab=update"
    assert (update_dir / "request" / "check").exists()

    response = await client.post(
        "/settings/update/upgrade", data={"csrf_token": csrf_token}, follow_redirects=False
    )
    assert response.status_code == 303
    assert (update_dir / "request" / "upgrade").exists()

    # A second click while it's pending says so instead of queueing more.
    response = await client.post("/settings/update/upgrade", data={"csrf_token": csrf_token})
    assert "already requested or running" in response.text

    async with db_session_factory() as session:
        actions = (await session.execute(select(AuditLogEntry.action))).scalars().all()
    assert actions.count("settings.app_update.check") == 1
    assert actions.count("settings.app_update.upgrade") == 1

    partial = await client.get("/settings/update/status")
    assert partial.status_code == 200
    assert 'hx-trigger="every 3s"' in partial.text
    assert "Update requested" in partial.text


async def test_upgrade_needs_csrf_and_manage(
    client: AsyncClient, login_as: Any, update_dir: Path
) -> None:
    _install(update_dir)
    _available(update_dir)
    response = await client.post("/settings/update/upgrade", data={})
    assert response.status_code in (400, 403)
    assert not (update_dir / "request" / "upgrade").exists()

    await login_as(client, permissions={Permission.SETTINGS_VIEW})
    page = await client.get("/settings?tab=update")
    assert page.status_code == 200
    assert 'action="/settings/update/upgrade"' not in page.text
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post("/settings/update/upgrade", data={"csrf_token": csrf_token})
    assert response.status_code == 403
    assert not (update_dir / "request" / "upgrade").exists()


async def test_post_without_watcher_shows_how_to_install(
    client: AsyncClient, update_dir: Path
) -> None:
    await client.get("/settings?tab=update")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post("/settings/update/check", data={"csrf_token": csrf_token})
    assert response.status_code == 200
    assert "not installed on the host" in response.text


# --- REST API ----------------------------------------------------------------


async def test_api_status_and_requests(
    client: AsyncClient, update_dir: Path, db_session_factory: Any
) -> None:
    headers = await _api_token(client)

    response = await client.post("/api/v1/settings/update/check", headers=headers)
    assert response.status_code == 409

    _install(update_dir)
    _available(update_dir)
    body = (await client.get("/api/v1/settings/update", headers=headers)).json()
    assert body["installed"] is True
    assert body["update_available"] is True
    assert body["available"]["remote_version"] == "9.9.9"
    assert body["current_version"] == APP_VERSION

    response = await client.post("/api/v1/settings/update/upgrade", headers=headers)
    assert response.status_code == 202
    assert response.json() == {"requested": "upgrade"}
    again = await client.post("/api/v1/settings/update/upgrade", headers=headers)
    assert again.status_code == 409

    async with db_session_factory() as session:
        actions = (await session.execute(select(AuditLogEntry.action))).scalars().all()
    assert "settings.app_update.upgrade" in actions


# --- scripts/self_update.py (the host side) -----------------------------------


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(  # noqa: S603 - fixed test arguments
        ["git", *args],  # noqa: S607
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _commit_version(repo: Path, version: str, message: str) -> None:
    path = repo / "app" / "core" / "version.py"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f'APP_VERSION = "{version}"\n')
    _git(repo, "add", ".")
    _git(repo, "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-qm", message)


@pytest.fixture
def checkout(tmp_path: Path) -> tuple[Path, Path]:
    """A checkout one release behind its origin, plus its self-update dir."""
    upstream = tmp_path / "upstream"
    upstream.mkdir()
    _git(upstream, "init", "-q", "-b", "main")
    _commit_version(upstream, "1.0.0", "First (1.0.0)")
    clone = tmp_path / "checkout"
    _git(tmp_path, "clone", "-q", str(upstream), str(clone))
    _commit_version(upstream, "1.1.0", "Second (1.1.0)")
    base = tmp_path / "self-update"
    (base / "request").mkdir(parents=True)
    (base / "status").mkdir()
    (base / "status" / "watcher.json").write_text('{"user": "t"}')
    return clone, base


def test_watcher_check_records_what_is_new(checkout: tuple[Path, Path]) -> None:
    root, base = checkout
    result = self_update.check(root, base)
    assert result["ok"] is True
    assert result["behind"] == 1
    assert result["remote_version"] == "1.1.0"
    assert result["local_version"] == "1.0.0"
    assert [c["subject"] for c in result["commits"]] == ["Second (1.1.0)"]
    # The app reads the very same file.
    status = app_update.read_status(base)
    assert status.update_available
    assert status.available is not None and status.available.remote_version == "1.1.0"


def test_watcher_takes_every_entry_and_runs_only_known_requests(
    checkout: tuple[Path, Path], tmp_path: Path
) -> None:
    root, base = checkout
    request = base / "request"
    (request / "upgrade").write_text("; rm -rf / # content is never read")
    (request / "something-else").write_text("")
    (request / "a-dir").mkdir()
    victim = tmp_path / "victim"
    victim.write_text("keep me")
    (request / "a-link").symlink_to(victim)

    ran: list[list[str]] = []

    def fake_upgrade(where: Path) -> list[str]:
        command = ["sh", "-c", f"cd {where} && git pull -q --ff-only && echo pulled"]
        ran.append(command)
        return command

    handled = self_update.handle_requests(root, base, fake_upgrade)
    assert handled == {"upgrade"}
    assert list(request.iterdir()) == []
    assert victim.read_text() == "keep me"
    assert len(ran) == 1

    state = json.loads((base / "status" / "upgrade.json").read_text())
    assert state["state"] == "succeeded"
    assert state["from_version"] == "1.0.0" and state["to_version"] == "1.1.0"
    assert "pulled" in (base / "status" / "upgrade.log").read_text()
    # Refreshed afterwards: nothing left to install.
    available = json.loads((base / "status" / "available.json").read_text())
    assert available["behind"] == 0


def test_watcher_records_a_failed_upgrade(checkout: tuple[Path, Path]) -> None:
    root, base = checkout
    (base / "request" / "upgrade").write_text("")
    self_update.handle_requests(root, base, lambda _root: ["sh", "-c", "echo nope; exit 3"])
    state = json.loads((base / "status" / "upgrade.json").read_text())
    assert state["state"] == "failed" and state["exit_code"] == 3
    run = app_update.read_status(base).upgrade
    assert run is not None and run.state == "failed"


def test_watcher_marks_a_cut_short_upgrade_interrupted(checkout: tuple[Path, Path]) -> None:
    root, base = checkout
    (base / "status" / "upgrade.json").write_text('{"state": "running"}')
    self_update.handle_requests(root, base)
    assert json.loads((base / "status" / "upgrade.json").read_text())["state"] == "interrupted"


def test_watcher_reports_a_dirty_checkout(checkout: tuple[Path, Path]) -> None:
    root, base = checkout
    (root / "app" / "core" / "version.py").write_text('APP_VERSION = "local"\n')
    assert self_update.check(root, base)["dirty"] is True


def test_watcher_check_failure_is_recorded(tmp_path: Path) -> None:
    base = tmp_path / "self-update"
    (base / "status").mkdir(parents=True)
    result = self_update.check(tmp_path, base)  # not a git checkout
    assert result["ok"] is False and result["error"]
