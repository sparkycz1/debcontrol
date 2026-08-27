from __future__ import annotations

import asyncio

from app.ssh.reachability import check_reachable


async def test_check_reachable_true_when_something_listens():
    async def _handle(reader, writer):
        writer.close()

    server = await asyncio.start_server(_handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        assert await check_reachable("127.0.0.1", port, timeout_seconds=2) is True
    finally:
        server.close()
        await server.wait_closed()


async def test_check_reachable_false_when_nothing_listens():
    # Bind to get a free port, then close it immediately so nothing answers there.
    probe = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port = probe.sockets[0].getsockname()[1]
    probe.close()
    await probe.wait_closed()

    assert await check_reachable("127.0.0.1", port, timeout_seconds=2) is False
