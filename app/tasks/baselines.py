"""Celery tasks that learn each machine's usual behavior
(`app.services.machine_baseline`): a nightly fan-out, one task per active
machine (never awaited inline, so a fleet of thousands spreads over the
workers). Tests call the underscore-prefixed coroutines directly.
"""

from __future__ import annotations

import asyncio
import logging
import uuid

from sqlalchemy import select

from app.db import session as db_session
from app.db.models.machine import Machine
from app.services import machine_baseline
from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)

# Four weeks of one machine's samples, read and sorted into buckets.
TASK_TIME_LIMIT_SECONDS = 10 * 60


async def _learn_machine_baseline(machine_id: str) -> bool:
    """True when a baseline was stored (the machine has any history)."""
    async with db_session.AsyncSessionLocal() as db:
        baseline = await machine_baseline.recompute(db, uuid.UUID(machine_id))
        await db.commit()
        return baseline is not None


@celery_app.task(
    name="app.tasks.baselines.learn_machine_baseline",
    time_limit=TASK_TIME_LIMIT_SECONDS,
    soft_time_limit=TASK_TIME_LIMIT_SECONDS - 30,
)
def learn_machine_baseline(machine_id: str) -> bool:
    return asyncio.run(_learn_machine_baseline(machine_id))


async def _learn_all_baselines() -> int:
    """Queue one `learn_machine_baseline` per active machine."""
    async with db_session.AsyncSessionLocal() as db:
        ids = (await db.execute(select(Machine.id).where(Machine.is_active))).scalars().all()
    for machine_id in ids:
        learn_machine_baseline.delay(str(machine_id))
    logger.info("Queued usual-behavior learning for %d machine(s)", len(ids))
    return len(ids)


@celery_app.task(name="app.tasks.baselines.learn_all_baselines")
def learn_all_baselines() -> int:
    return asyncio.run(_learn_all_baselines())
