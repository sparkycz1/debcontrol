"""Reusing one SSH connection per machine across background checks.

Every periodic check (monitoring sample, facts, packages, services,
readiness, update check, image-update check) used to open its own SSH
connection and close it again. On the managed machine each connection is
a full login: sshd's "Accepted …" line, a PAM session, a new logind
session and `session-N.scope`, and — whenever no other session of that
user is open — a start *and* stop of the whole `user@UID.service` user
manager. On a monitoring cadence that is hundreds of logins a day,
burying the machine's journal in debcontrol's own noise.

An SSH connection can carry any number of commands (one "exec channel"
each) behind a single login. So a Celery worker process now keeps the
connection it opened to a machine and runs the next check's command over
it, the same way OpenSSH's `ControlMaster` multiplexing does: no new
login, no new session, and — with one session held open — no user-manager
churn either.

How it fits together:

- `app.tasks.runner.run_in_worker_loop` runs a periodic task's coroutine on
  one event loop kept for the whole life of the worker process (instead of
  `asyncio.run()`'s fresh loop per task, which would strand every
  connection on a closed loop) and registers that loop here. Reuse only
  ever happens on that registered loop: a coroutine run anywhere else (the
  web app, a test, a task still using `asyncio.run`) gets a plain
  connect-run-close connection, exactly as before.
- `machine_connection(...)` hands out the cached connection when its
  identity still matches (address, port, account, pinned host key and a
  hash of the credential — rotating a key or re-pinning a host reconnects)
  and a cheap `true` probe over it succeeds; otherwise it connects afresh
  (same strict pinned-host-key verification, `app.ssh.client.open_connection`).
- Connections idle longer than **Settings → Checks & retention → Keep SSH
  connections open** (`AppSettings.ssh_connection_reuse_minutes`, 0 turns
  reuse off entirely) are closed the next time the process runs a task,
  and each process keeps at most `MAX_CONNECTIONS_PER_PROCESS`
  (least-recently-used closed first), so a large fleet can't exhaust a
  worker's file descriptors — it just falls back to reconnecting.

Only read-only collectors use this. Update runs, rollbacks, power actions,
the terminal and one-off commands keep their own dedicated connection.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import time
from collections import OrderedDict
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import TYPE_CHECKING

import asyncssh

from app.ssh.client import open_connection

if TYPE_CHECKING:
    from app.db.models.machine import Machine

logger = logging.getLogger(__name__)

MAX_CONNECTIONS_PER_PROCESS = 64
DEFAULT_IDLE_MINUTES = 15
# A cached connection gets this long to answer the `true` probe before
# it's treated as dead and replaced.
_PROBE_TIMEOUT_SECONDS = 5.0
# How long the "keep connections open" setting is cached per process.
_SETTING_REFRESH_SECONDS = 60.0


@dataclass
class _Entry:
    conn: asyncssh.SSHClientConnection
    identity: str
    last_used: float


_reuse_loop: asyncio.AbstractEventLoop | None = None
_entries: OrderedDict[str, _Entry] = OrderedDict()
_setting_cache: dict[str, float | None] = {"minutes": None, "read_at": 0.0}


def enable_for_loop(loop: asyncio.AbstractEventLoop) -> None:
    """Allow connection reuse for coroutines running on `loop` — called by
    `app.tasks.runner` for its per-process worker loop only."""
    global _reuse_loop
    if _reuse_loop is not loop:
        _entries.clear()
    _reuse_loop = loop


def reset() -> None:
    """Forget every cached connection and the registered loop (tests; a
    freshly forked worker child)."""
    global _reuse_loop
    _reuse_loop = None
    _entries.clear()
    _setting_cache.update(minutes=None, read_at=0.0)


def open_connection_count() -> int:
    return len(_entries)


def _identity(machine: Machine, secret: str | None) -> str:
    secret_hash = hashlib.sha256((secret or "").encode()).hexdigest()
    return "|".join(
        (
            machine.ip_address,
            str(machine.port),
            machine.username,
            machine.host_key_fingerprint or "",
            str(machine.auth_method),
            secret_hash,
        )
    )


def _close(entry: _Entry) -> None:
    with contextlib.suppress(Exception):
        entry.conn.close()


async def _idle_seconds() -> float:
    """`AppSettings.ssh_connection_reuse_minutes` in seconds, cached for a
    minute. 0 means reuse is off."""
    now = time.monotonic()
    cached = _setting_cache["minutes"]
    if cached is not None and now - (_setting_cache["read_at"] or 0.0) < _SETTING_REFRESH_SECONDS:
        return cached * 60
    minutes: float = DEFAULT_IDLE_MINUTES
    try:
        from app.core.app_settings import get_or_create_app_settings
        from app.db import session as db_session

        async with db_session.AsyncSessionLocal() as db:
            app_settings = await get_or_create_app_settings(db)
            minutes = float(app_settings.ssh_connection_reuse_minutes)
    except Exception:
        logger.warning("Could not read the SSH connection reuse setting", exc_info=True)
    _setting_cache.update(minutes=minutes, read_at=now)
    return minutes * 60


def _evict(idle_seconds: float, now: float) -> None:
    for key in [k for k, e in _entries.items() if now - e.last_used > idle_seconds]:
        _close(_entries.pop(key))
    while len(_entries) > MAX_CONNECTIONS_PER_PROCESS:
        _key, oldest = _entries.popitem(last=False)
        _close(oldest)


async def _alive(conn: asyncssh.SSHClientConnection) -> bool:
    if conn.is_closed():
        return False
    try:
        async with asyncio.timeout(_PROBE_TIMEOUT_SECONDS):
            result = await conn.run("true", check=False)
    except (asyncssh.Error, OSError, TimeoutError):
        return False
    return result.exit_status == 0


@contextlib.asynccontextmanager
async def machine_connection(
    machine: Machine, secret: str | None, timeout_seconds: int
) -> AsyncIterator[asyncssh.SSHClientConnection]:
    """An SSH connection to `machine` for the duration of the block —
    reused across tasks when this runs on the worker loop and reuse is on
    (see the module docstring), otherwise opened here and closed on exit."""
    loop = asyncio.get_running_loop()
    idle_seconds = await _idle_seconds() if loop is _reuse_loop else 0.0
    if idle_seconds <= 0:
        async with await open_connection(machine, secret, timeout_seconds) as conn:
            yield conn
        return

    now = time.monotonic()
    _evict(idle_seconds, now)
    key = str(machine.id)
    identity = _identity(machine, secret)
    entry = _entries.get(key)
    if entry is not None and (entry.identity != identity or not await _alive(entry.conn)):
        _close(_entries.pop(key))
        entry = None
    if entry is None:
        conn = await open_connection(machine, secret, timeout_seconds)
        entry = _Entry(conn=conn, identity=identity, last_used=now)
        _entries[key] = entry
        _evict(idle_seconds, now)
    _entries.move_to_end(key)

    try:
        yield entry.conn
    except (asyncssh.Error, OSError):
        # The connection itself broke mid-command — never hand it out again.
        if _entries.get(key) is entry:
            _close(_entries.pop(key))
        raise
    finally:
        entry.last_used = time.monotonic()
