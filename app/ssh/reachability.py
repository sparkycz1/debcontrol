"""Cheap machine "is it alive" check for the automatic per-minute status
badge, and (see `ReachabilityResult`) the "Availability" history on the
Monitoring tab.

This deliberately does NOT attempt an SSH handshake or authenticate — it's
just a raw TCP connect to the configured SSH port. That's enough to answer
"is something listening there right now" without the cost (or host-key
strictness) of a real SSH connection, and it's what's actually relevant for
an SSH management tool (a host that blocks ICMP but serves SSH should still
show as reachable, and vice versa). Real connectivity, including
authentication, is still verified by the "Test connection" button
(`app.ssh.client.test_connection`), which does the full pinned-host-key
SSH flow.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

DEFAULT_TIMEOUT_SECONDS = 5.0


@dataclass(frozen=True)
class ReachabilityResult:
    reachable: bool
    # How long the connect attempt took, in milliseconds. `None` for a
    # failed attempt — there's no meaningful "connect time" for a timeout
    # or refused connection, only for one that actually succeeded.
    latency_ms: float | None


async def check_reachable(
    ip_address: str, port: int, timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
) -> ReachabilityResult:
    """Attempt a TCP connection to (ip_address, port) and time it."""
    started = time.monotonic()
    try:
        async with asyncio.timeout(timeout_seconds):
            reader, writer = await asyncio.open_connection(ip_address, port)
    except (OSError, TimeoutError):
        return ReachabilityResult(reachable=False, latency_ms=None)

    latency_ms = (time.monotonic() - started) * 1000

    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return ReachabilityResult(reachable=True, latency_ms=latency_ms)
