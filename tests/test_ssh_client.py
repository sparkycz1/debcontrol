from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import asyncssh
import pytest

from app.db.models.machine import AuthMethod, Machine
from app.ssh.client import discover_host_key_fingerprint, open_connection
from app.ssh.exceptions import HostKeyMismatchError, UnknownHostKeyError

FINGERPRINT_HASH = "sha256"


async def test_open_connection_refuses_without_pinned_fingerprint():
    """No connection may be attempted at all without a confirmed key fingerprint."""
    machine = Machine(
        name="unpinned",
        ip_address="203.0.113.10",
        port=22,
        username="admin",
        auth_method=AuthMethod.PASSWORD,
        host_key_fingerprint=None,
    )

    with pytest.raises(UnknownHostKeyError):
        await open_connection(machine, secret="whatever", timeout_seconds=1)


class _AcceptAnyPasswordServer(asyncssh.SSHServer):
    """A minimal in-process SSH server for exercising the real handshake —
    this is deliberately not mocked: the bug this whole test file exists
    to catch (`known_hosts=None` silently skipping host-key validation
    entirely, see app/ssh/client.py's module docstring) only shows up
    against a real AsyncSSH connection, never against a hand-rolled stub."""

    def connection_made(self, connection: asyncssh.SSHServerConnection) -> None:
        self._connection = connection

    def begin_auth(self, username: str) -> bool:
        return False  # no auth required — any username/password is accepted

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        return True


async def _handle_client(process: asyncssh.SSHServerProcess[str]) -> None:
    process.exit(0)


@pytest.fixture
async def ssh_test_server() -> AsyncIterator[tuple[str, int, str]]:
    """A real, local, ephemeral SSH server. Yields (host, port, fingerprint)."""
    host_key = asyncssh.generate_private_key("ssh-ed25519")
    server = await asyncssh.create_server(
        _AcceptAnyPasswordServer,
        host="127.0.0.1",
        port=0,
        server_host_keys=[host_key],
        process_factory=_handle_client,
    )
    try:
        port = server.sockets[0].getsockname()[1]
        fingerprint = host_key.get_fingerprint(FINGERPRINT_HASH)
        yield "127.0.0.1", port, fingerprint
    finally:
        server.close()
        await server.wait_closed()


async def test_discover_host_key_fingerprint_matches_the_real_server_key(ssh_test_server):
    host, port, expected_fingerprint = ssh_test_server
    fingerprint = await discover_host_key_fingerprint(host, port, timeout_seconds=5)
    assert fingerprint == expected_fingerprint


async def test_open_connection_succeeds_with_the_correct_pinned_fingerprint(ssh_test_server):
    host, port, fingerprint = ssh_test_server
    machine = Machine(
        name="pinned-correctly",
        ip_address=host,
        port=port,
        username="whoever",
        auth_method=AuthMethod.PASSWORD,
        host_key_fingerprint=fingerprint,
    )

    conn = await open_connection(machine, secret="whatever", timeout_seconds=5)
    async with conn:
        pass  # reaching here at all means the host key was accepted


async def test_open_connection_rejects_a_different_key_than_the_pinned_one(ssh_test_server):
    """The regression test for the actual bug: `known_hosts=None` made
    AsyncSSH accept *any* server key without ever consulting
    `_PinnedSSHClient.validate_host_public_key` — a real MITM (a different
    key than the one pinned) would have gone through silently. This must
    fail loudly instead."""
    host, port, _real_fingerprint = ssh_test_server
    wrong_key = asyncssh.generate_private_key("ssh-ed25519")
    wrong_fingerprint = wrong_key.get_fingerprint(FINGERPRINT_HASH)

    machine = Machine(
        name="pinned-to-a-different-key",
        ip_address=host,
        port=port,
        username="whoever",
        auth_method=AuthMethod.PASSWORD,
        host_key_fingerprint=wrong_fingerprint,
    )

    with pytest.raises(HostKeyMismatchError):
        await open_connection(machine, secret="whatever", timeout_seconds=5)


async def test_discover_host_key_fingerprint_never_authenticates(ssh_test_server):
    """Discovery must stop at key exchange — no username/credentials sent,
    no userauth attempt reaching the server at all."""
    host, port, _fingerprint = ssh_test_server
    auth_attempted = False

    class _FlaggingServer(_AcceptAnyPasswordServer):
        def begin_auth(self, username: str) -> bool:
            nonlocal auth_attempted
            auth_attempted = True
            return False

    host_key = asyncssh.generate_private_key("ssh-ed25519")
    server = await asyncssh.create_server(
        _FlaggingServer,
        host="127.0.0.1",
        port=0,
        server_host_keys=[host_key],
        process_factory=_handle_client,
    )
    try:
        port2 = server.sockets[0].getsockname()[1]
        await discover_host_key_fingerprint("127.0.0.1", port2, timeout_seconds=5)
    finally:
        server.close()
        await server.wait_closed()

    # Give the event loop a beat in case the server would have processed a
    # (which it shouldn't) pending auth message.
    await asyncio.sleep(0)
    assert auth_attempted is False
