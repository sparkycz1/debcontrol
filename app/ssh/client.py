"""A thin layer over AsyncSSH for connecting to managed Debian machines.

Security principle — no blind "trust on first use":

1. `discover_host_key_fingerprint()` connects to a machine ONLY to learn its
   SSH host key fingerprint, and always deliberately aborts before
   authenticating. The fingerprint is shown to an operator, who must verify
   it through a channel outside this application (e.g. the hosting
   provider's console, or `ssh-keygen -lf` run on the machine itself) and
   only then explicitly confirm it.
2. Only after that human confirmation is the fingerprint stored against the
   machine (`Machine.host_key_fingerprint`).
3. Every subsequent connection (`open_connection`) then strictly verifies
   the presented key against that stored fingerprint — a mismatch
   immediately aborts the connection as a possible Man-in-the-Middle
   attack; it is never silently ignored.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import TYPE_CHECKING

import asyncssh

from app.ssh.exceptions import HostKeyMismatchError, SSHConnectionError, UnknownHostKeyError

if TYPE_CHECKING:
    from app.db.models.machine import Machine

FINGERPRINT_HASH = "sha256"


class _DiscoverySSHClient(asyncssh.SSHClient):
    """Learns the server's key fingerprint and always rejects — never authenticates."""

    def __init__(self) -> None:
        self.discovered_fingerprint: str | None = None

    def validate_host_public_key(
        self, host: str, addr: str, port: int, key: asyncssh.SSHKey
    ) -> bool:
        self.discovered_fingerprint = key.get_fingerprint(FINGERPRINT_HASH)
        return False


class _PinnedSSHClient(asyncssh.SSHClient):
    """Accepts the connection only if the server's key matches the pinned fingerprint."""

    def __init__(self, expected_fingerprint: str) -> None:
        self._expected_fingerprint = expected_fingerprint
        self.presented_fingerprint: str | None = None

    def validate_host_public_key(
        self, host: str, addr: str, port: int, key: asyncssh.SSHKey
    ) -> bool:
        self.presented_fingerprint = key.get_fingerprint(FINGERPRINT_HASH)
        return self.presented_fingerprint == self._expected_fingerprint


async def discover_host_key_fingerprint(hostname: str, port: int, timeout_seconds: int) -> str:
    """Learn the server's SHA256 host key fingerprint without ever trusting it.

    Returns the fingerprint for human verification. Never "trusts" anything
    on its own.
    """
    holder: dict[str, _DiscoverySSHClient] = {}

    def factory() -> _DiscoverySSHClient:
        client = _DiscoverySSHClient()
        holder["client"] = client
        return client

    try:
        async with asyncio.timeout(timeout_seconds):
            await asyncssh.connect(
                hostname,
                port=port,
                known_hosts=None,
                client_factory=factory,
                username="debcontrol-key-discovery",
            )
    except (asyncssh.Error, OSError, TimeoutError):
        pass  # expected: the factory deliberately rejects every connection

    client = holder.get("client")
    if client is None or client.discovered_fingerprint is None:
        raise SSHConnectionError(
            f"Could not determine the SSH host key fingerprint for {hostname}:{port}."
        )
    return client.discovered_fingerprint


def _build_connect_kwargs(
    machine: Machine,
    secret: str | None,
    client_factory: Callable[[], asyncssh.SSHClient],
) -> dict[str, object]:
    from app.db.models.machine import AuthMethod  # local import, see TYPE_CHECKING above

    kwargs: dict[str, object] = {
        "host": machine.ip_address,
        "port": machine.port,
        "username": machine.username,
        "known_hosts": None,
        "client_factory": client_factory,
        "client_keys": [],
    }
    if machine.auth_method == AuthMethod.PASSWORD:
        kwargs["password"] = secret
    else:
        if not secret:
            raise SSHConnectionError("Missing private key for authentication.")
        kwargs["client_keys"] = [asyncssh.import_private_key(secret)]
    return kwargs


async def open_connection(
    machine: Machine, secret: str | None, timeout_seconds: int
) -> asyncssh.SSHClientConnection:
    """Open an SSH connection to a machine with strict pinned host-key verification."""
    if not machine.host_key_fingerprint:
        raise UnknownHostKeyError(
            f"Machine {machine.ip_address} has no pinned SSH host key fingerprint — "
            "discover and confirm it first."
        )

    holder: dict[str, _PinnedSSHClient] = {}

    def factory() -> _PinnedSSHClient:
        client = _PinnedSSHClient(machine.host_key_fingerprint)  # type: ignore[arg-type]
        holder["client"] = client
        return client

    connect_kwargs = _build_connect_kwargs(machine, secret, factory)

    try:
        async with asyncio.timeout(timeout_seconds):
            return await asyncssh.connect(**connect_kwargs)
    except (asyncssh.Error, OSError, TimeoutError) as exc:
        client = holder.get("client")
        presented = client.presented_fingerprint if client else None
        if presented and presented != machine.host_key_fingerprint:
            raise HostKeyMismatchError(
                f"Server {machine.ip_address}:{machine.port} presented a different key "
                f"fingerprint ({presented}) than the pinned one "
                f"({machine.host_key_fingerprint}). Connection refused — this could be "
                "a Man-in-the-Middle attack."
            ) from exc
        raise SSHConnectionError(
            f"Connection to {machine.ip_address}:{machine.port} failed: {exc}"
        ) from exc


async def test_connection(machine: Machine, secret: str | None, timeout_seconds: int) -> str:
    """Check machine reachability and return the output of a simple diagnostic command."""
    async with await open_connection(machine, secret, timeout_seconds) as conn:
        result = await conn.run("uname -a", check=False, timeout=timeout_seconds)

    stdout = result.stdout
    if not stdout:
        return ""
    return (stdout if isinstance(stdout, str) else stdout.decode()).strip()
