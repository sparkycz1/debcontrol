"""Files watched for changes on a machine
(`app.services.watched_files`): the first reading is the baseline, later
differences are recorded and announced without their content, and the
diff is for `machine.manage`."""

from __future__ import annotations

import base64
from typing import Any

import pytest
from httpx2 import AsyncClient
from sqlalchemy import select

from app.db.models.machine_change import MachineChange
from app.db.models.machine_watched_file import MachineWatchedFile
from app.services import watched_files
from app.tasks import jobs
from tests.test_homelab_round import _add_machine
from tests.test_notification_throttle import _capture_webhook
from tests.test_update_history import _api_token


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def test_paths_must_be_plain_absolute_files() -> None:
    assert watched_files.parse_paths("/etc/ssh/sshd_config\n\n/etc/nginx/nginx.conf\n") == [
        "/etc/ssh/sshd_config",
        "/etc/nginx/nginx.conf",
    ]
    assert watched_files.parse_paths("/etc/a\n/etc/a\n") == ["/etc/a"]
    for bad in ("etc/passwd", "/etc/../shadow", "/etc/a b", "/etc/$(id)", "/etc/dir/", "/a;b"):
        with pytest.raises(watched_files.WatchedFilesError):
            watched_files.parse_paths(bad)
    with pytest.raises(watched_files.WatchedFilesError):
        watched_files.parse_paths("\n".join(f"/etc/f{i}" for i in range(21)))


def test_output_is_read_per_file() -> None:
    raw = (
        "===FILE 0 ok===\n" + _b64("Port 22\n") + "\n"
        "===FILE 1 missing===\n"
        "===FILE 2 ok===\n!!! not base64 !!!\n"
        "===FILE 3 too_large===\n"
        "===FILE 9 ok===\n" + _b64("ignored") + "\n"
    )

    readings = watched_files.parse_output(raw, 4)

    assert readings == {
        0: ("ok", "Port 22\n"),
        1: ("missing", None),
        2: ("unreadable", None),
        3: ("too_large", None),
    }
    command = watched_files.build_command(["/etc/ssh/sshd_config"])
    assert "base64 < /etc/ssh/sshd_config" in command
    with pytest.raises(ValueError):
        watched_files.build_command(["/etc/x; reboot"])


async def test_changes_are_recorded_announced_and_shown_as_a_diff(
    client: AsyncClient, db_session_factory: Any, monkeypatch: Any
) -> None:
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    posted = _capture_webhook(monkeypatch)
    machine_id = await _add_machine(db_session_factory, name="web1")
    base = f"/machines/{machine_id}/files"
    await client.get(base)
    csrf = client.cookies.get("csrftoken")
    await client.post(
        "/notifications/rules",
        data={
            "csrf_token": csrf,
            "name": "config",
            "enabled": "on",
            "event_types": "machine.config_changed",
            "delivery_channel": "webhook",
            "webhook_url": "https://hooks.example.com/x",
        },
    )

    refused = await client.post(
        base, data={"csrf_token": csrf, "paths": "relative/path"}, follow_redirects=False
    )
    saved = await client.post(
        base,
        data={"csrf_token": csrf, "paths": "/etc/ssh/sshd_config\n/etc/gone.conf"},
        follow_redirects=False,
    )
    versions = iter(
        [
            "Port 22\nPermitRootLogin no\nPasswordAuthentication no\n",
            "Port 22\nPermitRootLogin no\nPasswordAuthentication no\n",
            "Port 2222\nPermitRootLogin yes\nPasswordAuthentication no\nAllowUsers ops\n",
        ]
    )

    async def fake_run(*_args: Any, **_kwargs: Any) -> Any:
        class _Result:
            exit_status = 0
            # /etc/gone.conf sorts first.
            output = "===FILE 0 missing===\n===FILE 1 ok===\n" + _b64(next(versions)) + "\n"

        return _Result()

    monkeypatch.setattr(jobs, "run_command", fake_run)
    first = await jobs._check_watched_files(str(machine_id))
    same = await jobs._check_watched_files(str(machine_id))
    changed = await jobs._check_watched_files(str(machine_id))

    assert "files_error=" in refused.headers["location"]
    assert "files_notice=" in saved.headers["location"]
    assert (first["changed"], same["changed"], changed["changed"]) == (0, 0, 1)
    async with db_session_factory() as db:
        rows = {
            row.path: row
            for row in (await db.execute(select(MachineWatchedFile))).scalars().all()
        }
        history = list((await db.execute(select(MachineChange))).scalars().all())
    config = rows["/etc/ssh/sshd_config"]
    assert rows["/etc/gone.conf"].state == "missing"
    assert (config.lines_added, config.lines_removed) == (3, 2)
    # Stored encrypted, never as it is.
    assert config.content_encrypted is not None and b"Port 2222" not in config.content_encrypted
    assert [(h.field, h.old_value, h.new_value) for h in history] == [
        ("watched_file", "/etc/ssh/sshd_config", "+3 / -2 lines")
    ]
    # The notification names the file, not its lines.
    assert len(posted) == 1
    assert "/etc/ssh/sshd_config" in posted[0]["body"]
    assert "PermitRootLogin" not in posted[0]["body"]

    page = await client.get(f"{base}?diff={config.id}")
    timeline = await client.get(f"/machines/{machine_id}/history")
    headers = await _api_token(client)
    listed = (
        await client.get(f"/api/v1/machines/{machine_id}/watched-files", headers=headers)
    ).json()
    diff = (
        await client.get(
            f"/api/v1/machines/{machine_id}/watched-files/{config.id}/diff", headers=headers
        )
    ).json()

    assert "+Port 2222" in page.text and "-PermitRootLogin no" in page.text
    assert "Watched file" in timeline.text and "/etc/ssh/sshd_config" in timeline.text
    assert {f["path"]: f["state"] for f in listed} == {
        "/etc/gone.conf": "missing",
        "/etc/ssh/sshd_config": "ok",
    }
    assert all("content" not in f for f in listed)
    assert "+AllowUsers ops" in diff["diff"]


async def test_removing_a_path_forgets_the_file(
    client: AsyncClient, db_session_factory: Any
) -> None:
    machine_id = await _add_machine(db_session_factory, name="web2")
    headers = await _api_token(client)
    url = f"/api/v1/machines/{machine_id}/watched-files"

    both = await client.put(url, headers=headers, json={"paths": ["/etc/a", "/etc/b"]})
    one = await client.put(url, headers=headers, json={"paths": ["/etc/b"]})
    bad = await client.put(url, headers=headers, json={"paths": ["/etc/../x"]})

    assert [f["path"] for f in both.json()] == ["/etc/a", "/etc/b"]
    assert [f["path"] for f in one.json()] == ["/etc/b"]
    assert bad.status_code == 422
