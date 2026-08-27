"""arq worker — processes jobs from the Redis queue.

Run (the `worker` service in docker-compose.yml handles this in Docker):
    arq app.tasks.worker.WorkerSettings
"""

from __future__ import annotations

import logging

from arq.connections import RedisSettings

from app.core.config import get_settings
from app.core.logging import configure_logging
from app.tasks.jobs import ping_machine

logger = logging.getLogger(__name__)


async def startup(ctx: dict[str, object]) -> None:
    configure_logging(get_settings().log_level)
    logger.info("arq worker started.")


async def shutdown(ctx: dict[str, object]) -> None:
    logger.info("arq worker shutting down.")


def _redis_settings() -> RedisSettings:
    return RedisSettings.from_dsn(get_settings().redis_url)


class WorkerSettings:
    functions = [ping_machine]
    on_startup = startup
    on_shutdown = shutdown
    redis_settings = _redis_settings()
    max_jobs = 10
    job_timeout = 60
