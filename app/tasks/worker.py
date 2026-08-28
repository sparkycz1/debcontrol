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
from app.scheduling.builtin_actions import register_builtin_actions
from app.scheduling.jobs import run_due_scheduled_tasks, run_scheduled_task
from app.tasks.jobs import (
    check_all_machine_updates,
    check_machine_updates,
    ping_all_machines,
    refresh_all_machine_facts,
    refresh_machine_facts,
    run_machine_update,
    send_machine_power_command,
    test_machine_connection,
)

logger = logging.getLogger(__name__)

# Populates app.scheduling.actions' registry — must happen before the worker
# (or anything else in this process) evaluates or runs a scheduled task.
register_builtin_actions()


async def startup(ctx: dict[str, Any]) -> None:
    configure_logging(get_settings().log_level)
    logger.info("arq worker started.")
    # Kick off the first facts/update-availability sweeps shortly after
    # startup rather than waiting a full FACTS_REFRESH_INTERVAL_SECONDS;
    # each then keeps rescheduling itself.
    redis = ctx["redis"]
    await redis.enqueue_job("refresh_all_machine_facts", _defer_by=timedelta(seconds=10))
    await redis.enqueue_job("check_all_machine_updates", _defer_by=timedelta(seconds=15))


async def shutdown(ctx: dict[str, Any]) -> None:
    logger.info("arq worker shutting down.")


def _redis_settings() -> RedisSettings:
    return RedisSettings.from_dsn(get_settings().redis_url)


class WorkerSettings:
    functions = [
        test_machine_connection,
        refresh_machine_facts,
        refresh_all_machine_facts,
        check_all_machine_updates,
        send_machine_power_command,
        run_due_scheduled_tasks,
        run_scheduled_task,
        # apt update/upgrade(-check) can legitimately run far longer than
        # the default job_timeout below — give both their own budget.
        func(run_machine_update, timeout=get_settings().update_timeout_seconds),
        func(check_machine_updates, timeout=get_settings().update_timeout_seconds),
    ]
    cron_jobs = [
        cron(ping_all_machines, second=0, unique=True),
        # Cron expressions are minute-grained anyway, so a fixed per-minute
        # tick (rather than a configurable self-rescheduling interval, like
        # facts/update-check sweeps use) is the natural fit here.
        cron(run_due_scheduled_tasks, second=0, unique=True),
    ]
    on_startup = startup
    on_shutdown = shutdown
    redis_settings = _redis_settings()
    max_jobs = 10
    job_timeout = 60
