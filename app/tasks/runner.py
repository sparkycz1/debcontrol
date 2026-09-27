"""One event loop per worker process, for tasks that reuse SSH connections.

Most Celery tasks here run their coroutine with `asyncio.run()` — a brand
new event loop per task, closed again at the end. An asyncssh connection
belongs to the loop it was opened on, so under `asyncio.run()` nothing can
outlive the task. `run_in_worker_loop` instead keeps a single loop for the
whole life of the (forked) worker process and runs each task to completion
on it, which is what lets `app.ssh.pool` keep one SSH connection per
machine open between periodic checks.

The database side is unaffected: worker children use `NullPool`
(`app.tasks.celery_app._init_worker_process`), so no pooled DB connection
is ever carried from one task to the next either way. A fork (new child
process) gets a new loop — the parent's is never touched.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Coroutine
from typing import Any

from app.ssh import pool

_loop: asyncio.AbstractEventLoop | None = None
_loop_pid: int | None = None


def _worker_loop() -> asyncio.AbstractEventLoop:
    global _loop, _loop_pid
    if _loop is None or _loop.is_closed() or _loop_pid != os.getpid():
        _loop = asyncio.new_event_loop()
        _loop_pid = os.getpid()
        pool.reset()
        pool.enable_for_loop(_loop)
    return _loop


def run_in_worker_loop[T](coro: Coroutine[Any, Any, T]) -> T:
    """Run `coro` to completion on this process's long-lived loop."""
    loop = _worker_loop()
    asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)
