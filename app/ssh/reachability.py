"""Cheap machine "is it alive" check for the automatic per-minute status badge.

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

DEFAULT_TIMEOUT_SECONDS = 5.0


async def check_reachable(
    ip_address: str, port: int, timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
) -> bool:
    """Return True if a TCP connection to (ip_address, port) succeeds."""
    try:
        async with asyncio.timeout(timeout_seconds):
            reader, writer = await asyncio.open_connection(ip_address, port)
    except (OSError, TimeoutError):
        return False

    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return True
