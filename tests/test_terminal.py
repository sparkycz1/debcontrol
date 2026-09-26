from __future__ import annotations

import uuid
from types import SimpleNamespace

from sqlalchemy import select

import app.web.routes.terminal_ws as terminal_ws_module
from app.auth.sessions import create_session
from app.db.models.audit_log import AuditLogEntry
from app.db.models.machine import AuthMethod, Machine
from app.db.models.role import Permission, Role, RolePermission
from app.db.models.user import AuthProvider, User
from app.web.routes.terminal_ws import _authenticate, terminal_websocket
from tests.test_web import _create_machine, _pin_host_key

# --- Helpers for the low-level `_authenticate`/`terminal_websocket` unit
# tests below, which exercise the WebSocket handler directly (no browser,
# no real ASGI transport needed) since that's the only realistic way to
# test a WebSocket route in this suite — see this module's own tests for
# the HTTP-reachable parts (the page shell, permission gating on it).


class _FakeApp:
    def __init__(self, db_session_factory: object) -> None:
        self.state = SimpleNamespace(db_session_factory=db_session_factory)


class _FakeWebSocket:
    def __init__(
        self,
        db_session_factory: object,
        *,
        token: str | None = None,
        origin: str | None = "http://testserver",
    ) -> None:
        self.app = _FakeApp(db_session_factory)
        self.cookies: dict[str, str] = {"session": token} if token else {}
        self.headers: dict[str, str] = {"host": "testserver"}
        if origin is not None:
            self.headers["origin"] = origin
        self.closed: tuple[int, str | None] | None = None
        self.accepted = False
        self.sent_text: list[str] = []

    async def accept(self) -> None:
        self.accepted = True

    async def close(self, code: int = 1000, reason: str | None = None) -> None:
        self.closed = (code, reason)

    async def send_text(self, data: str) -> None:
        self.sent_text.append(data)

    async def send_bytes(self, data: bytes) -> None:
        pass

    async def receive(self) -> dict[str, object]:
        # Simulates a client that never sends anything else — the fake SSH
        # process below reaches EOF immediately, which is what actually
        # ends the session in these tests; this just has to stay pending
        # until cancelled.
        import asyncio

        await asyncio.sleep(999)
        return {"type": "websocket.receive"}  # pragma: no cover - never reached


class _FakeStdout:
    async def read(self, n: int) -> bytes:
        return b""  # immediate EOF: the fake remote shell exited right away


class _FakeStdin:
    def write(self, data: bytes) -> None:
        pass


class _FakeProcess:
    def __init__(self) -> None:
        self.stdout = _FakeStdout()
        self.stdin = _FakeStdin()
        self.terminated = False

    def change_terminal_size(self, cols: int, rows: int) -> None:
        pass

    def terminate(self) -> None:
        self.terminated = True


class _FakeConnection:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


async def _make_machine(db_session_factory: object, *, pinned: bool = True) -> uuid.UUID:
    async with db_session_factory() as db:  # type: ignore[operator]
        machine = Machine(
            name="term-machine",
            ip_address="10.0.0.5",
            port=22,
            username="admin",
            auth_method=AuthMethod.SSH_KEY,
            host_key_fingerprint="SHA256:fakefingerprint" if pinned else None,
        )
        db.add(machine)
        await db.commit()
        await db.refresh(machine)
        return machine.id


async def _make_session_token(
    db_session_factory: object, *, permissions: set[Permission]
) -> str:
    async with db_session_factory() as db:  # type: ignore[operator]
        role = Role(name=f"role-{uuid.uuid4()}")
        role.permission_grants = [RolePermission(permission=p) for p in permissions]
        db.add(role)
        await db.flush()
        user = User(
            username=f"user-{uuid.uuid4().hex[:8]}",
            auth_provider=AuthProvider.LOCAL,
            is_active=True,
            role=role,
        )
        db.add(user)
        await db.flush()
        _session, raw_token = await create_session(
            db, user, ip_address="testclient", user_agent="pytest"
        )
        await db.commit()
        return raw_token


# --- `_authenticate` (the WebSocket handshake gate) ---


async def test_authenticate_rejects_missing_session_cookie(db_session_factory):
    machine_id = await _make_machine(db_session_factory)
    ws = _FakeWebSocket(db_session_factory)

    result = await _authenticate(ws, machine_id)  # type: ignore[arg-type]

    assert result is None
    assert ws.closed is not None
    assert ws.closed[0] == 1008


async def test_authenticate_rejects_user_without_permission(db_session_factory):
    machine_id = await _make_machine(db_session_factory)
    token = await _make_session_token(db_session_factory, permissions=set())
    ws = _FakeWebSocket(db_session_factory, token=token)

    result = await _authenticate(ws, machine_id)  # type: ignore[arg-type]

    assert result is None
    assert ws.closed is not None
    assert ws.closed[0] == 1008


async def test_authenticate_rejects_machine_without_pinned_fingerprint(db_session_factory):
    machine_id = await _make_machine(db_session_factory, pinned=False)
    token = await _make_session_token(
        db_session_factory, permissions={Permission.ACTION_TERMINAL}
    )
    ws = _FakeWebSocket(db_session_factory, token=token)

    result = await _authenticate(ws, machine_id)  # type: ignore[arg-type]

    assert result is None
    assert ws.closed is not None
    assert ws.closed[0] == 1008


async def test_authenticate_succeeds_with_permission_and_pinned_machine(db_session_factory):
    machine_id = await _make_machine(db_session_factory)
    token = await _make_session_token(
        db_session_factory, permissions={Permission.ACTION_TERMINAL}
    )
    ws = _FakeWebSocket(db_session_factory, token=token)

    result = await _authenticate(ws, machine_id)  # type: ignore[arg-type]

    assert result is not None
    user, machine = result
    assert machine.id == machine_id
    assert user.has_permission(Permission.ACTION_TERMINAL)
    assert ws.closed is None


async def test_authenticate_rejects_a_cross_origin_handshake(db_session_factory):
    """A valid session cookie is not enough when the handshake comes from a
    page on another origin (e.g. a sibling subdomain the SameSite=Strict
    cookie still reaches) — see `app.auth.websocket_origin`."""
    machine_id = await _make_machine(db_session_factory)
    token = await _make_session_token(
        db_session_factory, permissions={Permission.ACTION_TERMINAL}
    )
    ws = _FakeWebSocket(db_session_factory, token=token, origin="https://evil.testserver")

    result = await _authenticate(ws, machine_id)  # type: ignore[arg-type]

    assert result is None
    assert ws.closed == (1008, "Cross-origin request refused.")


async def test_authenticate_allows_a_handshake_without_origin(db_session_factory):
    """No Origin header means no browser (and so no ambient cookie to
    hijack) — the session cookie check alone applies."""
    machine_id = await _make_machine(db_session_factory)
    token = await _make_session_token(
        db_session_factory, permissions={Permission.ACTION_TERMINAL}
    )
    ws = _FakeWebSocket(db_session_factory, token=token, origin=None)

    assert await _authenticate(ws, machine_id) is not None  # type: ignore[arg-type]


# --- Full session lifecycle: audit logging, connection teardown ---


async def test_terminal_websocket_logs_open_and_close_and_tears_down_ssh(
    db_session_factory, monkeypatch
):
    machine_id = await _make_machine(db_session_factory)
    token = await _make_session_token(
        db_session_factory, permissions={Permission.ACTION_TERMINAL}
    )

    fake_conn = _FakeConnection()
    fake_process = _FakeProcess()

    async def _fake_open_shell_session(machine, secret, timeout_seconds, *, term_type, term_size):
        return fake_conn, fake_process

    monkeypatch.setattr(terminal_ws_module, "open_shell_session", _fake_open_shell_session)

    ws = _FakeWebSocket(db_session_factory, token=token)
    await terminal_websocket(ws, machine_id)  # type: ignore[arg-type]

    # Torn down on every exit path — see the module docstring.
    assert fake_process.terminated
    assert fake_conn.closed
    assert ws.accepted

    async with db_session_factory() as db:
        result = await db.execute(select(AuditLogEntry).order_by(AuditLogEntry.sequence))
        entries = list(result.scalars().all())

    actions = [entry.action for entry in entries]
    assert "machine.terminal.open" in actions
    assert "machine.terminal.close" in actions

    close_entry = next(e for e in entries if e.action == "machine.terminal.close")
    assert close_entry.details is not None
    assert "duration_seconds" in close_entry.details
    assert close_entry.target_type == "machine"
    assert close_entry.target_id == str(machine_id)


async def test_terminal_websocket_closes_with_error_when_ssh_connection_fails(
    db_session_factory, monkeypatch
):
    from app.ssh.exceptions import SSHConnectionError

    machine_id = await _make_machine(db_session_factory)
    token = await _make_session_token(
        db_session_factory, permissions={Permission.ACTION_TERMINAL}
    )

    async def _fake_open_shell_session(machine, secret, timeout_seconds, *, term_type, term_size):
        raise SSHConnectionError("connection refused")

    monkeypatch.setattr(terminal_ws_module, "open_shell_session", _fake_open_shell_session)

    ws = _FakeWebSocket(db_session_factory, token=token)
    await terminal_websocket(ws, machine_id)  # type: ignore[arg-type]

    assert ws.accepted
    assert any("connection refused" in text for text in ws.sent_text)

    # No SSH session ever started, so there's nothing to open/close an
    # audit entry for.
    async with db_session_factory() as db:
        result = await db.execute(select(AuditLogEntry))
        entries = list(result.scalars().all())
    assert not any(e.action.startswith("machine.terminal.") for e in entries)


# --- The HTTP-reachable page shell (`GET /machines/{id}/terminal`) ---


async def test_terminal_page_requires_action_terminal_permission(
    client, login_as, db_session_factory
):
    """A user with every *other* machine permission (view/manage/updates/
    power) but not `action.terminal` must still be refused — this is its
    own dedicated permission, not implied by any of the others."""
    await client.get("/machines/new")
    machine_id = await _create_machine(client, client.cookies.get("csrftoken"))
    await _pin_host_key(db_session_factory, machine_id)

    await login_as(
        client,
        permissions={
            Permission.MACHINE_VIEW,
            Permission.MACHINE_MANAGE,
            Permission.ACTION_UPDATES,
            Permission.ACTION_POWER,
        },
    )
    response = await client.get(f"/machines/{machine_id}/terminal")
    assert response.status_code == 403


async def test_terminal_page_refuses_without_pinned_fingerprint(client):
    await client.get("/machines/new")
    machine_id = await _create_machine(client, client.cookies.get("csrftoken"))

    response = await client.get(f"/machines/{machine_id}/terminal")
    assert response.status_code == 400


async def test_terminal_page_loads_with_permission_and_pinned_fingerprint(
    client, db_session_factory
):
    await client.get("/machines/new")
    machine_id = await _create_machine(client, client.cookies.get("csrftoken"))
    await _pin_host_key(db_session_factory, machine_id)

    # The `client` fixture is logged in with every permission, including
    # ACTION_TERMINAL.
    response = await client.get(f"/machines/{machine_id}/terminal")
    assert response.status_code == 200
    assert "terminal-container" in response.text


async def test_terminal_page_loads_the_csp_safe_renderer(client, db_session_factory):
    """Regression guard: xterm.js's default DOM renderer draws ANSI colors
    via dynamically injected <style> elements, which this app's CSP
    (`style-src 'self'`, no `unsafe-inline`) silently blocks — every color
    code renders as plain foreground-only text, with no error visible
    anywhere except the browser console. The WebGL addon draws on a
    <canvas> instead, and xterm-csp.css carries the rules the DOM fallback
    would otherwise inject. See `terminal.js`'s own comment."""
    await client.get("/machines/new")
    machine_id = await _create_machine(client, client.cookies.get("csrftoken"))
    await _pin_host_key(db_session_factory, machine_id)

    response = await client.get(f"/machines/{machine_id}/terminal")

    assert response.status_code == 200
    assert '<script src="/static/js/xterm-addon-webgl.min.js?v=' in response.text
    assert '<link rel="stylesheet" href="/static/css/xterm-csp.css?v=' in response.text
    assert "xterm-addon-canvas" not in response.text


async def test_detail_page_shows_terminal_link_only_with_permission_and_pinned_key(
    client, login_as, db_session_factory
):
    await client.get("/machines/new")
    machine_id = await _create_machine(client, client.cookies.get("csrftoken"))

    # No pinned fingerprint yet: even the fully-permissioned `client` sees
    # a disabled link, not an active one.
    detail = await client.get(f"/machines/{machine_id}")
    assert "Open terminal" not in detail.text or "button-disabled" in detail.text

    await _pin_host_key(db_session_factory, machine_id)
    detail = await client.get(f"/machines/{machine_id}")
    assert f"/machines/{machine_id}/terminal" in detail.text

    await login_as(client, permissions={Permission.MACHINE_VIEW})
    detail = await client.get(f"/machines/{machine_id}")
    assert "Terminal</h2>" not in detail.text
