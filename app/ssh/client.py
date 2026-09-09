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

`known_hosts=([], [], [])` below (an explicit "no trusted keys, no CA keys,
no revoked keys, and don't touch any known_hosts file" tuple, per AsyncSSH's
own `match_known_hosts()` docs) is NOT the same as `known_hosts=None`, and
the difference matters a lot: passing `None` tells AsyncSSH's connection
itself has no `_trusted_host_keys` set to compare against, which skips
calling `SSHClient.validate_host_public_key()` entirely and accepts
*any* presented key — silently. That would make `_PinnedSSHClient` below
never actually get consulted, meaning `open_connection()` would accept a
different key than the one pinned without ever raising
`HostKeyMismatchError` — a MITM completely undetected, in direct
contradiction to point 3 above. The empty-tuple form keeps an empty (but
non-`None`) trusted-key set, which *does* make AsyncSSH fall through to
the callback for every key. See `test_ssh_client.py`'s
`test_open_connection_rejects_a_different_key_than_the_pinned_one` for the
regression test that would catch this again.
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

# See the module docstring for why this specific value, not `None`.
_NO_TRUSTED_KNOWN_HOSTS: tuple[list[object], list[object], list[object]] = ([], [], [])

# Restricts every *authenticated* connection (`open_connection`, below) to
# algorithms NIST SP 800-52/SP 800-56A/FIPS 197 approve — see
# wiki/Architecture.md's "FIPS alignment" section for the full reasoning.
# AsyncSSH's own (much broader) default negotiation still applies to
# `discover_host_key_fingerprint` above, deliberately: that probe exists
# specifically to *learn* whatever host key type a machine actually has,
# so it must not filter any out.
#
# `server_host_key_algs` is intentionally left at AsyncSSH's default rather
# than narrowed here too — this app already pins host keys by their exact
# fingerprint, not their algorithm, and a machine already pinned on an
# Ed25519 key (EdDSA isn't yet on the approved list) would otherwise
# immediately fail to connect. Narrowing the channel's own key exchange/
# encryption/MAC is the real FIPS-relevant boundary; which signature
# algorithm authenticated a host key already pinned out-of-band is a
# smaller concern than that.
_FIPS_KEX_ALGS = (
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
    "diffie-hellman-group18-sha512",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group14-sha256",
)
_FIPS_ENCRYPTION_ALGS = (
    "aes256-gcm@openssh.com",
    "aes128-gcm@openssh.com",
    "aes256-ctr",
    "aes192-ctr",
    "aes128-ctr",
)
_FIPS_MAC_ALGS = (
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512",
    "hmac-sha2-256",
)


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

    Uses AsyncSSH's own `get_server_host_key()` — it stops right after key
    exchange and never proceeds to authentication at all (no username, no
    credentials, nothing sent past the point of learning the key), which is
    both simpler and more reliable than emulating the same thing with a
    custom `SSHClient` subclass returning `False` from
    `validate_host_public_key()` (a previous version of this function did
    exactly that with `known_hosts=None`, which — per the module
    docstring's explanation of that flag — never actually invoked the
    callback at all, so it silently proceeded toward real authentication
    instead of stopping at key exchange, and never captured a fingerprint).

    Returns the fingerprint for human verification. Never "trusts" anything
    on its own.
    """
    try:
        async with asyncio.timeout(timeout_seconds):
            key = await asyncssh.get_server_host_key(hostname, port=port)
    except (asyncssh.Error, OSError, TimeoutError) as exc:
        raise SSHConnectionError(
            f"Could not determine the SSH host key fingerprint for {hostname}:{port}."
        ) from exc

    if key is None:
        raise SSHConnectionError(
            f"Could not determine the SSH host key fingerprint for {hostname}:{port}."
        )
    return key.get_fingerprint(FINGERPRINT_HASH)


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
        "known_hosts": _NO_TRUSTED_KNOWN_HOSTS,
        "client_factory": client_factory,
        "client_keys": [],
        "kex_algs": _FIPS_KEX_ALGS,
        "encryption_algs": _FIPS_ENCRYPTION_ALGS,
        "mac_algs": _FIPS_MAC_ALGS,
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


async def open_shell_session(
    machine: Machine,
    secret: str | None,
    timeout_seconds: int,
    *,
    term_type: str,
    term_size: tuple[int, int],
) -> tuple[asyncssh.SSHClientConnection, asyncssh.SSHClientProcess[bytes]]:
    """Open a connection (same strict pinned host-key verification as
    `open_connection` — this deliberately calls it rather than re-building
    connect kwargs itself) and start an interactive PTY shell on it, for the
    web terminal feature (`app/web/routes/terminal_ws.py`).

    Returns the raw connection and process; the caller owns both and is
    responsible for closing them (`conn.close()` / `process.terminate()`)
    when the terminal session ends, including on every error path — there's
    no context-manager wrapper here because the caller needs to hold both
    open for the lifetime of a WebSocket, not just one request/response.

    `encoding=None` (the default here) makes `process.stdout`/`.stdin` deal
    in raw `bytes` rather than decoded `str` — the right choice for a
    terminal, which relays arbitrary byte streams (including partial UTF-8
    sequences and ANSI escape codes) rather than parsed text.

    Requests `LANG`/`LC_ALL=C.UTF-8` as the session's locale — without it,
    an interactive shell's locale is whatever the remote account's own
    login environment defaults to (commonly the POSIX/"C" locale on a
    minimal, non-interactively-provisioned server), which makes ncurses
    apps (htop, less, ...) draw meters/borders with plain ASCII characters
    instead of the Unicode block/box-drawing ones they'd otherwise use.
    "C.UTF-8" is a locale every glibc system has built in with no
    `locale-gen` step required, unlike e.g. "en_US.UTF-8". This is a
    best-effort SSH env request, not a guarantee: sshd only forwards
    variables its own `AcceptEnv`/`SetEnv` allows (Debian/Ubuntu's default
    sshd_config allows `LANG`/`LC_*`) — a server that doesn't accept these
    just ignores the request rather than failing the connection.
    """
    conn = await open_connection(machine, secret, timeout_seconds)
    try:
        process = await conn.create_process(
            term_type=term_type,
            term_size=term_size,
            encoding=None,
            stderr=asyncssh.STDOUT,
            env={"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
        )
    except (asyncssh.Error, OSError) as exc:
        conn.close()
        raise SSHConnectionError(f"Failed to start an interactive shell: {exc}") from exc
    return conn, process


async def test_connection(machine: Machine, secret: str | None, timeout_seconds: int) -> str:
    """Check machine reachability and return the output of a simple diagnostic command."""
    async with await open_connection(machine, secret, timeout_seconds) as conn:
        result = await conn.run("uname -a", check=False, timeout=timeout_seconds)

    stdout = result.stdout
    if not stdout:
        return ""
    return (stdout if isinstance(stdout, str) else stdout.decode()).strip()
