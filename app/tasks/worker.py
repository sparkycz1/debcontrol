"""arq worker — processes jobs from the Redis queue.

Run (the `worker` service in docker-compose.yml handles this in Docker):
    arq app.tasks.worker.WorkerSettings
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from arq import cron, func
from arq.connections import RedisSettings

from app.core.config import get_settings
from app.core.logging import configure_logging
from app.tasks.jobs import (
    ping_all_machines,
    refresh_all_machine_facts,
    refresh_machine_facts,
    run_machine_update,
    test_machine_connection,
)

logger = logging.getLogger(__name__)


async def startup(ctx: dict[str, Any]) -> None:
    configure_logging(get_settings().log_level)
    logger.info("arq worker started.")
    # Kick off the first facts sweep shortly after startup rather than
    # waiting a full FACTS_REFRESH_INTERVAL_SECONDS; it then keeps
    # rescheduling itself (see `refresh_all_machine_facts`).
    redis = ctx["redis"]
    await redis.enqueue_job("refresh_all_machine_facts", _defer_by=timedelta(seconds=10))


async def shutdown(ctx: dict[str, Any]) -> None:
    logger.info("arq worker shutting down.")


def _redis_settings() -> RedisSettings:
    return RedisSettings.from_dsn(get_settings().redis_url)


class WorkerSettings:
    functions = [
        test_machine_connection,
        refresh_machine_facts,
        refresh_all_machine_facts,
        # apt update/upgrade can legitimately run far longer than the
        # default job_timeout below — give it its own budget.
        func(run_machine_update, timeout=get_settings().update_timeout_seconds),
    ]
    cron_jobs = [cron(ping_all_machines, second=0, unique=True)]
    on_startup = startup
    on_shutdown = shutdown
    redis_settings = _redis_settings()
    max_jobs = 10
    job_timeout = 60
