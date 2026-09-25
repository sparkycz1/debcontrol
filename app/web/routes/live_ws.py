"""WebSocket relay for one machine's "something changed" push notifications
(`app/services/live_updates.py`) — what lets the Overview/Monitoring/
Updates tabs' htmx panels refresh the moment a background job finishes
instead of waiting out their own polling interval. See
`app/web/static/js/live-updates.js` for the browser side.

Auth follows the exact same pattern `app/web/routes/terminal_ws.py`
documents in its own module docstring, for the same reason:
`app.auth.middleware` never runs for WebSocket requests, so this
re-implements a session-cookie + permission check by hand. Gated behind
`MACHINE_VIEW` rather than `MACHINE_MANAGE` or `ACTION_TERMINAL` — this
socket only ever emits a `kind` string telling the client which already-
permission-checked htmx panel to re-fetch, never any machine data itself,
so anyone who could load the Overview tab in the first place learns
nothing new from it.

**Protocol**: text frames only, each `{"kind": "status"|"facts"|
"packages"|"services"|"updates"}` — see `live_updates.py`'s `Kind`
constants. One-way (server to client); anything the client sends is
ignored. No DB/SSH access happens here at all — this is pure Redis
pub/sub relay, so a slow or stuck machine can never block this socket.
"""

from __future__ import annotations

import asyncio
import contextlib
import uuid

from fastapi import APIRouter, WebSocket, status
from redis.asyncio.client import PubSub

from app.auth.sessions import SESSION_COOKIE_NAME, get_valid_session
from app.auth.websocket_origin import is_same_origin
from app.db.models.machine import Machine
from app.db.models.role import Permission
from app.services.access_scope import can_see_machine
from app.services.live_updates import channel_for

router = APIRouter()

_POLICY_VIOLATION = status.WS_1008_POLICY_VIOLATION

# Idle sockets are cheap (pure Redis pub/sub, nothing per-connection) but
# not free — a hard cap means an abandoned browser tab doesn't hold one
# open forever. A viewer with the tab still open just reconnects (see
# live-updates.js's retry loop), invisibly.
_SESSION_MAX_SECONDS = 6 * 60 * 60  # 6 hours


async def _authenticate(websocket: WebSocket, machine_id: uuid.UUID) -> Machine | None:
    """Returns the machine if this connection may subscribe to its channel,
    or `None` after already closing the socket with an explanatory reason."""
    # Cross-site WebSocket hijacking guard — see `app.auth.websocket_origin`.
    if not is_same_origin(websocket.headers):
        await websocket.close(code=_POLICY_VIOLATION, reason="Cross-origin request refused.")
        return None

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
        if not user.has_permission(Permission.MACHINE_VIEW):
            await websocket.close(code=_POLICY_VIOLATION, reason="Missing permission.")
            return None
        machine: Machine | None = await db.get(Machine, machine_id)
        if machine is None or not await can_see_machine(db, user, machine):
            await websocket.close(code=_POLICY_VIOLATION, reason="Machine not found.")
            return None
    return machine


@router.websocket("/machines/{machine_id}/live/ws")
async def machine_live_websocket(websocket: WebSocket, machine_id: uuid.UUID) -> None:
    machine = await _authenticate(websocket, machine_id)
    if machine is None:
        return

    await websocket.accept()

    redis = websocket.app.state.redis
    pubsub = redis.pubsub()
    await pubsub.subscribe(channel_for(str(machine.id)))
    try:
        listen_task = asyncio.ensure_future(_relay(websocket, pubsub))
        # Watching for the client closing its end is the only reason this
        # needs a second task at all — this socket never expects any
        # message from the client, only its disconnect.
        disconnect_task = asyncio.ensure_future(_watch_disconnect(websocket))
        timeout_task = asyncio.ensure_future(asyncio.sleep(_SESSION_MAX_SECONDS))
        try:
            await asyncio.wait(
                {listen_task, disconnect_task, timeout_task}, return_when=asyncio.FIRST_COMPLETED
            )
        finally:
            for task in (listen_task, disconnect_task, timeout_task):
                task.cancel()
            for task in (listen_task, disconnect_task, timeout_task):
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task
    finally:
        with contextlib.suppress(Exception):
            await pubsub.unsubscribe(channel_for(str(machine.id)))
        with contextlib.suppress(Exception):
            await pubsub.aclose()
        with contextlib.suppress(Exception):
            await websocket.close(code=status.WS_1000_NORMAL_CLOSURE)


async def _relay(websocket: WebSocket, pubsub: PubSub) -> None:
    async for message in pubsub.listen():
        if message.get("type") != "message":
            continue
        data = message.get("data")
        if isinstance(data, bytes):
            data = data.decode("utf-8", errors="replace")
        if isinstance(data, str):
            await websocket.send_text(data)


async def _watch_disconnect(websocket: WebSocket) -> None:
    while True:
        message = await websocket.receive()
        if message["type"] == "websocket.disconnect":
            return
