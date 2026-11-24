"""Celery tasks for configuration backups (`app.services.config_backup`):
one backup per machine, and the daily retention and check of the
repository. Tests call the underscore-prefixed coroutines directly.
"""

from __future__ import annotations

import asyncio
import uuid

from app.db import session as db_session
from app.services import config_backup
from app.tasks.celery_app import celery_app

# A backup copies /etc over SSH and stores it; restic may wait up to
# `RETRY_LOCK` for the daily prune.
TASK_TIME_LIMIT_SECONDS = 60 * 60


async def _run_config_backup(run_id: str) -> str:
    return await config_backup.run_backup(uuid.UUID(run_id))


@celery_app.task(
    name="app.tasks.config_backup.run_config_backup",
    time_limit=TASK_TIME_LIMIT_SECONDS,
    soft_time_limit=TASK_TIME_LIMIT_SECONDS - 60,
)
def run_config_backup(run_id: str) -> str:
    return asyncio.run(_run_config_backup(run_id))


async def _config_backup_maintenance() -> str | None:
    async with db_session.AsyncSessionLocal() as db:
        return await config_backup.run_maintenance(db)


@celery_app.task(
    name="app.tasks.config_backup.config_backup_maintenance",
    time_limit=2 * TASK_TIME_LIMIT_SECONDS,
    soft_time_limit=2 * TASK_TIME_LIMIT_SECONDS - 60,
)
def config_backup_maintenance() -> str | None:
    return asyncio.run(_config_backup_maintenance())
