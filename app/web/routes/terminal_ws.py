"""The interactive web terminal's WebSocket endpoint — the byte-relay half
of the feature (`app/web/routes/machines.py`'s `terminal_page` serves the
page shell that connects here).

**Why this can't just use `require_permission`/`app.auth.middleware` like
every other route**: `app.auth.middleware.require_auth` is registered via
`@app.middleware("http")` in `app.main` — Starlette only ever invokes
`http`-scoped middleware for `scope["type"] == "http"` requests, and never
for `"websocket"` ones. A WebSocket connection reaches this handler having
gone through *no* auth check at all. This module therefore re-implements,
by hand, the same two checks every other page gets for free:

1. A valid session cookie, via the exact same `app.auth.sessions.
   get_valid_session` the HTTP middleware itself calls (same revocation/
   expiry/`is_active` semantics — nothing new here, just called from a
   different place).
2. `Permission.ACTION_TERMINAL` on that session's user, since this feature
   is gated behind its own dedicated permission (see the comment on it in
   `app/db/models/role.py`) — the single most powerful thing this app can
   do (arbitrary command execution as whatever user/sudo rights the
   machine's configured account has).

Either failing closes the socket with `1008` (policy violation) *before*
accepting the connection and before anything SSH-related is attempted —
never accept-then-fail, which would let a client believe it has a live
terminal for a moment.

**Protocol**: binary WebSocket frames carry raw terminal bytes in both
directions (client keystrokes in, remote PTY output out); text frames carry
JSON control messages — currently just `{"type": "resize", "cols": .., "rows": ..}`
from the client, and `{"type": "error", "message": ..}` from the server for
a failure that happens before there's a PTY to relay bytes from at all.

**Session lifecycle**: `TERMINAL_SESSION_MAX_SECONDS` (2 hours) is a hard
cap on one session's wall-clock duration, closed server-side regardless of
activity — long enough for a real, uninterrupted admin session (installing
something, chasing down a problem, editing several files), short enough
that a forgotten/abandoned browser tab against this app's most powerful
capability doesn't hold an authenticated, potentially root-capable SSH
connection open indefinitely. There's no separate idle timeout on top of
it. The SSH connection and process are always torn down in a `finally`
block — on a clean disconnect, an error, or the hard cap firing — so there
is never a leaked SSH connection on any exit path.

Only the session's start and end are audit-logged (`machine.terminal.open`/
`.close`, with duration on close) — not keystrokes or output, which would
mean recording everything typed/seen in a potentially root-capable shell,
secrets included. This matches how the rest of this app treats "which SSH
round trip happened, by whom" as the audit-worthy fact, not a full
transcript of what it did (see `app/audit.py`'s module docstring).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

import asyncssh
from fastapi import APIRouter, WebSocket, status
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.audit import log_event
from app.auth.sessions import SESSION_COOKIE_NAME, get_valid_session
from app.core.config import get_settings
from app.db.models.machine import Machine
from app.db.models.role import Permission
from app.db.models.user import User
from app.services.access_scope import can_see_machine
from app.ssh.client import open_shell_session
from app.ssh.credentials import resolve_machine_credential
from app.ssh.exceptions import SSHConnectionError

router = APIRouter()

# See the module docstring for the reasoning behind this specific value.
TERMINAL_SESSION_MAX_SECONDS = 2 * 60 * 60  # 2 hours

_TERM_TYPE = "xterm-256color"
_DEFAULT_TERM_SIZE = (80, 24)
# Refuse an obviously-bogus resize request rather than passing it straight
# through to AsyncSSH's `change_terminal_size` — a client is untrusted input
# here just like any form field.
_MIN_TERM_DIM = 1
_MAX_TERM_DIM = 1000

_POLICY_VIOLATION = status.WS_1008_POLICY_VIOLATION


async def _authenticate(
    websocket: WebSocket, machine_id: uuid.UUID
) -> tuple[User, Machine] | None:
    """Returns (user, machine) if the connection is allowed to proceed, or
    `None` after already closing the socket with an explanatory reason."""
    raw_token = websocket.cookies.get(SESSION_COOKIE_NAME)
    if not raw_token:
        await websocket.close(code=_POLICY_VIOLATION, reason="Not authenticated.")
        return None

    db_session_factory = websocket.app.state.db_session_factory
    async with db_session_factory() as db:
        session = await get_valid_session(db, raw_token)
    if session is None:
        await websocket.close(code=_POLICY_VIOLATION, reason="Not authenticated.")
        return None

    user = session.user
    if not user.has_permission(Permission.ACTION_TERMINAL):
        await websocket.close(code=_POLICY_VIOLATION, reason="Missing permission.")
        return None

    async with db_session_factory() as db:
        machine = await db.get(Machine, machine_id)
        # A machine outside this account's machine-group scope is reported
        # as missing, never as forbidden — the same rule the HTTP routes
        # follow (see `app.services.access_scope`). The page shell at
        # `GET /machines/{id}/terminal` already 404s, but this socket
        # authenticates independently of it and must not rely on that.
        if machine is None or not await can_see_machine(db, user, machine):
            await websocket.close(code=_POLICY_VIOLATION, reason="Machine not found.")
            return None
        if not machine.host_key_fingerprint:
            await websocket.close(
                code=_POLICY_VIOLATION,
                reason="Machine has no pinned SSH host key fingerprint.",
            )
            return None
    return user, machine


async def _relay_output(
    websocket: WebSocket, process: asyncssh.SSHClientProcess[bytes]
) -> None:
    """Reads raw bytes from the remote PTY and forwards them as binary
    WebSocket frames — see the module docstring's protocol note (binary
    frames are terminal bytes, text frames are JSON control messages)."""
    while True:
        chunk = await process.stdout.read(65536)
        if not chunk:
            return
        await websocket.send_bytes(chunk)


async def _relay_input(websocket: WebSocket, process: asyncssh.SSHClientProcess[bytes]) -> None:
    """Reads from the WebSocket and either writes raw bytes to the remote
    shell's stdin (binary frames) or handles a control message (text
    frames — currently just `resize`)."""
    while True:
        message = await websocket.receive()
        if message["type"] == "websocket.disconnect":
            return
        data = message.get("bytes")
        if data is not None:
            process.stdin.write(data)
            continue
        text = message.get("text")
        if text is None:
            continue
        try:
            control = json.loads(text)
        except ValueError:
            continue
        if not isinstance(control, dict) or control.get("type") != "resize":
            continue
        cols, rows = control.get("cols"), control.get("rows")
        if (
            isinstance(cols, int)
            and isinstance(rows, int)
            and _MIN_TERM_DIM <= cols <= _MAX_TERM_DIM
            and _MIN_TERM_DIM <= rows <= _MAX_TERM_DIM
        ):
            with contextlib.suppress(Exception):
                process.change_terminal_size(cols, rows)


async def _log_terminal_event(
    db_session_factory: async_sessionmaker[AsyncSession],
    *,
    action: str,
    summary: str,
    machine: Machine,
    user: User,
    details: dict[str, Any] | None,
) -> None:
    """`app.audit.log_event` normally derives `actor`/`ip_address` from a
    `Request` — there is no `Request` here (this is a WebSocket), so `actor`
    is passed explicitly instead, same as any other background-job-style
    caller with no HTTP request behind it (see `app.audit.log_event`'s
    docstring). `ip_address` is left `None`: a WebSocket's originating
    address isn't tracked anywhere else in this app's audit trail either,
    and `websocket.client` isn't always populated depending on the ASGI
    server/proxy setup, so it isn't a reliable enough signal to add here
    without more work than this pass warrants."""
    async with db_session_factory() as db:
        await log_event(
            db,
            action=action,
            summary=summary,
            target_type="machine",
            target_id=machine.id,
            target_label=machine.name,
            actor=user.username,
            details=details,
        )


@router.websocket("/machines/{machine_id}/terminal/ws")
async def terminal_websocket(websocket: WebSocket, machine_id: uuid.UUID) -> None:
    authenticated = await _authenticate(websocket, machine_id)
    if authenticated is None:
        return
    user, machine = authenticated

    settings = get_settings()
    db_session_factory = websocket.app.state.db_session_factory
    async with db_session_factory() as db:
        secret = await resolve_machine_credential(machine, db)

    await websocket.accept()

    conn: asyncssh.SSHClientConnection | None = None
    process: asyncssh.SSHClientProcess[bytes] | None = None
    started_at = datetime.now(UTC)
    close_reason = "Session ended."
    # Only log a "close" event if "open" was actually logged — a connection
    # that never got established (see the `SSHConnectionError` branch below)
    # never started a session worth recording the end of.
    session_opened = False
    try:
        try:
            conn, process = await open_shell_session(
                machine,
                secret,
                settings.ssh_connect_timeout,
                term_type=_TERM_TYPE,
                term_size=_DEFAULT_TERM_SIZE,
            )
        except SSHConnectionError as exc:
            await websocket.send_text(json.dumps({"type": "error", "message": str(exc)}))
            return

        session_opened = True
        await _log_terminal_event(
            db_session_factory,
            action="machine.terminal.open",
            summary=f'Opened terminal to "{machine.name}"',
            machine=machine,
            user=user,
            details=None,
        )

        output_task: asyncio.Task[None] = asyncio.ensure_future(
            _relay_output(websocket, process)
        )
        input_task: asyncio.Task[None] = asyncio.ensure_future(_relay_input(websocket, process))
        timeout_task: asyncio.Task[None] = asyncio.ensure_future(
            asyncio.sleep(TERMINAL_SESSION_MAX_SECONDS)
        )
        try:
            done, _pending = await asyncio.wait(
                {output_task, input_task, timeout_task}, return_when=asyncio.FIRST_COMPLETED
            )
            if timeout_task in done:
                close_reason = "Session time limit reached."
        finally:
            for task in (output_task, input_task, timeout_task):
                task.cancel()
            for task in (output_task, input_task, timeout_task):
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task
    finally:
        if process is not None:
            with contextlib.suppress(Exception):
                process.terminate()
        if conn is not None:
            with contextlib.suppress(Exception):
                conn.close()

        if session_opened:
            duration_seconds = (datetime.now(UTC) - started_at).total_seconds()
            await _log_terminal_event(
                db_session_factory,
                action="machine.terminal.close",
                summary=f'Closed terminal to "{machine.name}" after {duration_seconds:.0f}s',
                machine=machine,
                user=user,
                details={"duration_seconds": round(duration_seconds, 1)},
            )
            with contextlib.suppress(Exception):
                await websocket.close(code=status.WS_1000_NORMAL_CLOSURE, reason=close_reason)
        else:
            with contextlib.suppress(Exception):
                await websocket.close(
                    code=status.WS_1011_INTERNAL_ERROR, reason="SSH connection failed."
                )
