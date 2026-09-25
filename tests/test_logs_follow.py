"""Live log following: the `-f` command builder (`app.ssh.logs.
build_follow_command`) and the WebSocket handler (`app/web/routes/
logs_ws.py`), driven directly with the same fakes as tests/test_terminal.py."""

from __future__ import annotations

import json

import pytest
from sqlalchemy import select

import app.web.routes.logs_ws as logs_ws_module
from app.db.models.audit_log import AuditLogEntry
from app.db.models.role import Permission
from app.ssh.exceptions import SSHConnectionError
from app.ssh.logs import LogAccessError, build_follow_command
from app.web.routes.logs_ws import follow_logs_websocket
from tests.test_terminal import (
    _FakeConnection,
    _FakeWebSocket,
    _make_machine,
    _make_session_token,
)


def test_follow_journal_command():
    assert build_follow_command(source="journal", path="", container="", search="") == (
        "journalctl --no-pager -f -n 50"
    )
    command = build_follow_command(source="journal", path="", container="", search="a b")
    assert command.endswith("-g 'a b'")


def test_follow_file_command_quotes_and_filters():
    command = build_follow_command(
        source="file", path="/var/log/syslog", container="", search="o'k"
    )
    assert command.startswith("tail -n 50 -F -- /var/log/syslog 2>&1")
    assert "grep --line-buffered -F --" in command
    assert "'o'\"'\"'k'" in command


def test_follow_file_outside_allowed_paths_is_refused():
    with pytest.raises(LogAccessError):
        build_follow_command(source="file", path="/etc/shadow", container="", search="")


def test_follow_docker_command_validates_container():
    command = build_follow_command(source="docker", path="", container="web-1", search="")
    assert "$D logs -f --tail 50 --timestamps web-1 2>&1" in command
    with pytest.raises(LogAccessError):
        build_follow_command(source="docker", path="", container="x;rm -rf /", search="")
    with pytest.raises(LogAccessError):
        build_follow_command(source="nope", path="", container="", search="")


class _Params(_FakeWebSocket):
    def __init__(self, *args: object, params: dict[str, str], **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self.query_params = params


class _LinesStdout:
    def __init__(self, lines: list[str]) -> None:
        self._lines = list(lines)

    async def readline(self) -> str:
        return self._lines.pop(0) if self._lines else ""


class _LinesProcess:
    def __init__(self, lines: list[str]) -> None:
        self.stdout = _LinesStdout(lines)
        self.terminated = False

    def terminate(self) -> None:
        self.terminated = True


async def test_follow_requires_terminal_permission(db_session_factory):
    machine_id = await _make_machine(db_session_factory)
    token = await _make_session_token(db_session_factory, permissions={Permission.MACHINE_VIEW})
    ws = _Params(db_session_factory, token=token, params={"source": "journal"})

    await follow_logs_websocket(ws, machine_id)  # type: ignore[arg-type]

    assert not ws.accepted
    assert ws.closed is not None and ws.closed[0] == 1008


async def test_follow_rejects_invalid_source_before_accepting(db_session_factory):
    machine_id = await _make_machine(db_session_factory)
    token = await _make_session_token(
        db_session_factory, permissions={Permission.ACTION_TERMINAL}
    )
    ws = _Params(
        db_session_factory, token=token, params={"source": "file", "path": "/etc/shadow"}
    )

    await follow_logs_websocket(ws, machine_id)  # type: ignore[arg-type]

    assert not ws.accepted
    assert ws.closed is not None and ws.closed[0] == 1008


async def test_follow_streams_lines_audits_and_tears_down(db_session_factory, monkeypatch):
    machine_id = await _make_machine(db_session_factory)
    token = await _make_session_token(
        db_session_factory, permissions={Permission.ACTION_TERMINAL}
    )
    process = _LinesProcess(["first\n", "second\r\n"])
    conn = _FakeConnection()
    commands: list[str] = []

    async def _create_process(command: str, **kwargs: object) -> _LinesProcess:
        commands.append(command)
        return process

    conn.create_process = _create_process  # type: ignore[attr-defined]

    async def _fake_open(machine, secret, timeout_seconds):
        return conn

    monkeypatch.setattr(logs_ws_module, "open_connection", _fake_open)
    ws = _Params(db_session_factory, token=token, params={"source": "journal"})

    await follow_logs_websocket(ws, machine_id)  # type: ignore[arg-type]

    frames = [json.loads(text) for text in ws.sent_text]
    assert frames[:2] == [{"t": "line", "v": "first"}, {"t": "line", "v": "second"}]
    assert frames[-1]["t"] == "end"
    assert commands == ["journalctl --no-pager -f -n 50"]
    assert process.terminated and conn.closed

    async with db_session_factory() as db:
        actions = [e.action for e in (await db.execute(select(AuditLogEntry))).scalars()]
    assert "machine.logs.follow" in actions
    assert "machine.logs.follow_end" in actions


async def test_follow_reports_connection_failure(db_session_factory, monkeypatch):
    machine_id = await _make_machine(db_session_factory)
    token = await _make_session_token(
        db_session_factory, permissions={Permission.ACTION_TERMINAL}
    )

    async def _fail(machine, secret, timeout_seconds):
        raise SSHConnectionError("connection refused")

    monkeypatch.setattr(logs_ws_module, "open_connection", _fail)
    ws = _Params(db_session_factory, token=token, params={"source": "journal"})

    await follow_logs_websocket(ws, machine_id)  # type: ignore[arg-type]

    assert any("connection refused" in text for text in ws.sent_text)
    async with db_session_factory() as db:
        actions = [e.action for e in (await db.execute(select(AuditLogEntry))).scalars()]
    assert not any(a.startswith("machine.logs.follow") for a in actions)


async def test_logs_page_offers_follow_button(client, db_session_factory, celery_calls):
    from tests.test_onboarding import _make_machine as _make_onboarded_machine

    machine_id = await _make_onboarded_machine(db_session_factory)

    response = await client.get(f"/machines/{machine_id}/logs", params={"search": "x y"})

    assert response.status_code == 200
    assert f"/machines/{machine_id}/logs/follow/ws?source=journal" in response.text
    assert "search=x%20y" in response.text
    assert "data-log-follow" in response.text
