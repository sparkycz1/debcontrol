"""Live log following over a WebSocket — the Logs tab's *Follow live*
button. Streams `journalctl -f` / `tail -F` / `docker logs -f` (see
`app.ssh.logs.build_follow_command`) line by line until the browser
disconnects or `FOLLOW_MAX_SECONDS` passes.

Authentication mirrors `app/web/routes/terminal_ws.py` exactly (a
WebSocket never passes through the HTTP auth middleware): a valid session
cookie, `action.terminal` (the same permission the Logs tab needs), the
machine inside the account's scope, and a pinned host key — all checked
before the socket is accepted. Only the start and end are audit-logged
(`machine.logs.follow` / `machine.logs.follow_end`), never the content.

Protocol: server → client JSON text frames only — `{"t": "line", "v":
"..."}` per log line, `{"t": "error", "v": "..."}`, and `{"t": "end",
"v": "reason"}` just before closing. The client sends nothing.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import uuid
from datetime import UTC, datetime

import asyncssh
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status

from app.core.app_settings import get_or_create_app_settings
from app.ssh.client import open_connection
from app.ssh.credentials import resolve_machine_credential
from app.ssh.exceptions import SSHConnectionError
from app.ssh.logs import LogAccessError, build_follow_command
from app.ssh.shell import with_root_shim
from app.web.routes.terminal_ws import _authenticate, _log_terminal_event

router = APIRouter()

# A forgotten tab shouldn't hold an SSH connection open forever.
FOLLOW_MAX_SECONDS = 60 * 60
# One absurdly long line (a minified JSON blob) shouldn't flood the page.
_MAX_LINE_CHARS = 10_000


async def _send(websocket: WebSocket, kind: str, value: str) -> None:
    await websocket.send_text(json.dumps({"t": kind, "v": value}))


async def _stream(websocket: WebSocket, stdout: asyncssh.SSHReader[str]) -> None:
    while True:
        line = await stdout.readline()
        if not line:
            return
        await _send(websocket, "line", line.rstrip("\r\n")[:_MAX_LINE_CHARS])


async def _wait_for_disconnect(websocket: WebSocket) -> None:
    with contextlib.suppress(WebSocketDisconnect):
        while True:
            message = await websocket.receive()
            if message["type"] == "websocket.disconnect":
                return


@router.websocket("/machines/{machine_id}/logs/follow/ws")
async def follow_logs_websocket(websocket: WebSocket, machine_id: uuid.UUID) -> None:
    authenticated = await _authenticate(websocket, machine_id)
    if authenticated is None:
        return
    user, machine = authenticated

    params = websocket.query_params
    source = params.get("source", "journal")
    path = params.get("path", "").strip()
    container = params.get("container", "").strip()
    search = params.get("search", "")
    priority = params.get("priority", "")
    unit = params.get("unit", "")
    try:
        command = build_follow_command(
            source=source,
            path=path,
            container=container,
            search=search,
            priority=priority,
            unit=unit,
        )
    except LogAccessError as exc:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason=str(exc)[:120])
        return

    db_session_factory = websocket.app.state.db_session_factory
    async with db_session_factory() as db:
        secret = await resolve_machine_credential(machine, db)
        app_settings = await get_or_create_app_settings(db)

    await websocket.accept()
    labels = {"journal": "the journal", "file": f'"{path}"', "docker": f'container "{container}"'}
    label = labels.get(source, source)

    try:
        conn = await open_connection(machine, secret, app_settings.ssh_connect_timeout)
    except SSHConnectionError as exc:
        with contextlib.suppress(Exception):
            await _send(websocket, "error", str(exc))
            await websocket.close(code=status.WS_1011_INTERNAL_ERROR)
        return

    started_at = datetime.now(UTC)
    end_reason = "Stopped."
    await _log_terminal_event(
        db_session_factory,
        action="machine.logs.follow",
        summary=f'Started following {label} on "{machine.name}"',
        machine=machine,
        user=user,
        details={"source": source, "search": search.strip() or None},
    )
    process: asyncssh.SSHClientProcess[str] | None = None
    try:
        process = await conn.create_process(with_root_shim(command), errors="replace")
        stream_task = asyncio.ensure_future(_stream(websocket, process.stdout))
        timeout_task = asyncio.ensure_future(asyncio.sleep(FOLLOW_MAX_SECONDS))
        tasks = {stream_task, timeout_task, asyncio.ensure_future(_wait_for_disconnect(websocket))}
        try:
            done, _pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            if timeout_task in done:
                end_reason = "Time limit reached — follow again to continue."
            elif stream_task in done:
                end_reason = "The log stream ended."
        finally:
            for task in tasks:
                task.cancel()
            for task in tasks:
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task
    except asyncssh.Error as exc:
        end_reason = f"Error: {exc}"
    finally:
        if process is not None:
            with contextlib.suppress(Exception):
                process.terminate()
        with contextlib.suppress(Exception):
            conn.close()
        duration = (datetime.now(UTC) - started_at).total_seconds()
        await _log_terminal_event(
            db_session_factory,
            action="machine.logs.follow_end",
            summary=f'Stopped following {label} on "{machine.name}" after {duration:.0f}s',
            machine=machine,
            user=user,
            details={"duration_seconds": round(duration, 1)},
        )
        with contextlib.suppress(Exception):
            await _send(websocket, "end", end_reason)
            await websocket.close(code=status.WS_1000_NORMAL_CLOSURE)
