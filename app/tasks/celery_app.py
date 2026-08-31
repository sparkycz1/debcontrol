"""Celery application: the app's one and only background task queue.

Run (both handled by docker-compose.yml — the `worker` and `beat` services):

    celery -A app.tasks.celery_app worker --loglevel=info --concurrency=10
    celery -A app.tasks.celery_app beat   --loglevel=info

Broker *and* result backend are the same Redis instance the rest of the app
already uses (`REDIS_URL`) — the result backend is not optional here: several
HTTP handlers (see `app/web/routes/machines.py`) enqueue a task and then wait
inline for its return value, which only works if results are actually stored.

Two things in here are less obvious than they look; both are load-bearing.


Fork safety: why the DB engine is rebuilt in every worker child
--------------------------------------------------------------
Celery's default worker pool is `prefork`. The parent process imports the
whole application (this module, `app.tasks.jobs`, and through them
`app.db.session`) and *then* forks N child processes. `app/db/session.py`
builds its async engine and session factory as module-level singletons at
import time, so without intervention every forked child would inherit the
exact same asyncpg connection pool — the same already-open TCP sockets to
Postgres — as its siblings and its parent.

That is not a "probably fine" situation. Two processes writing into one
socket interleave their protocol frames; one process closing a connection
yanks it out from under another; asyncpg's own per-connection state (prepared
statement cache, transaction status) becomes a lie in the child that did not
create it. The failure mode is not a clean crash either — it looks like
sporadic `InterfaceError`/`InternalClientError`, results delivered for the
wrong query, or a worker that wedges. And it would be invisible here: the
test suite runs against in-memory SQLite in a single process, so nothing
below would ever reproduce it. It only bites a real deployment.

The `worker_process_init` handler below therefore throws away whatever the
child inherited and constructs a fresh engine and session factory *inside*
each child, after the fork. Every job body reaches the factory through the
module (`db_session.AsyncSessionLocal(...)`, never a `from ... import
AsyncSessionLocal` binding captured at import time) precisely so that this
rebind is actually seen.


Explicit task names
-------------------
Every task is registered with an explicit `name=` rather than Celery's
auto-derived "module.function" default. Beat entries, the `.delay()` call
sites, and any task already sitting in Redis all refer to a task by *name*;
if the name were derived from the file layout, moving or renaming a module
would silently orphan queued messages and beat entries instead of failing
loudly. The names happen to match today's dotted paths, but they are now a
stable contract, not a coincidence.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from celery import Celery
from celery.schedules import crontab
from celery.signals import worker_process_init
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import get_settings
from app.core.logging import configure_logging

logger = logging.getLogger(__name__)

settings = get_settings()
configure_logging(settings.log_level)

celery_app = Celery(
    "debcontrol",
    broker=settings.redis_url,
    backend=settings.redis_url,
    # The modules holding @celery_app.task functions. Listed rather than
    # `autodiscover_tasks()`d — there are only a few, and naming them means
    # a broken one fails loudly at worker startup instead of quietly
    # registering nothing.
    #
    # This MUST stay a lazy `include=` list rather than plain `import`
    # statements at the bottom of this file: those task modules import (via
    # app.services.machine_actions) app.scheduling.builtin_actions, which
    # imports back into them, so importing them here at module-definition
    # time is a circular import. Celery imports these itself, once, when a
    # worker or beat process boots — after this module is fully loaded.
    include=["app.tasks.jobs", "app.tasks.ai_jobs", "app.scheduling.jobs"],
)

celery_app.conf.update(
    # JSON only — never pickle. Task arguments here are plain strings (UUIDs,
    # enum values) by design, and refusing pickle means a compromised Redis
    # can't hand the worker arbitrary objects to deserialize.
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    # The whole app stores and reasons about timestamps in UTC (see the
    # models); the beat schedule below has to agree, or the daily sweeps
    # would drift with the container's TZ setting.
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    # Default per-task wall-clock ceiling. The three apt-driven tasks
    # (run/check/preview update) legitimately run far longer and override
    # this with `time_limit=UPDATE_TIMEOUT_SECONDS` on their own decorator —
    # see app/tasks/jobs.py.
    task_time_limit=60,
    # One task at a time per child process. Every job here is a single SSH
    # round trip or a single DB sweep; fetching a second one to sit in a
    # child's memory while the first runs would only make a restart lose
    # more work.
    worker_prefetch_multiplier=1,
    # How long a task's result stays in Redis (the result backend) before
    # Celery expires the key. Celery's own default is 1 day — generous for
    # this app's actual usage: most of the fan-out sweep tasks below
    # (refresh_machine_facts/packages, check_machine_updates, one per
    # machine, every FACTS_REFRESH_INTERVAL_SECONDS) are pure fire-and-forget
    # `.delay()` calls that nothing ever reads the result of; only a handful
    # of web routes actually call `.get(timeout=...)` on one, and always
    # within seconds of enqueueing it. At a fleet size in the hundreds/
    # thousands, a full day's worth of these unread results sitting in Redis
    # is pure waste — one hour is more than enough headroom.
    result_expires=3600,
)

# --- Periodic work (Celery Beat) ---------------------------------------------
#
# The three fleet sweeps run on a configurable interval taken from Settings,
# which is why they are `timedelta(...)` schedules rather than crontabs.
#
# NOTE: these intervals are read once, here, when the *beat* process starts.
# Changing REACHABILITY_CHECK_INTERVAL_SECONDS / FACTS_REFRESH_INTERVAL_SECONDS
# takes effect on the next restart of the `beat` service, not live.
#
# Beat has no persisted "last run" on a fresh start, so each entry fires once
# shortly after startup on its own — which is exactly the behaviour the old
# queue needed a hand-written "kick off the first sweep" hook to get.
celery_app.conf.beat_schedule = {
    "ping-all-machines": {
        "task": "app.tasks.jobs.ping_all_machines",
        "schedule": timedelta(seconds=settings.reachability_check_interval_seconds),
    },
    "refresh-all-machine-facts": {
        "task": "app.tasks.jobs.refresh_all_machine_facts",
        "schedule": timedelta(seconds=settings.facts_refresh_interval_seconds),
    },
    "refresh-all-machine-packages": {
        "task": "app.tasks.jobs.refresh_all_machine_packages",
        "schedule": timedelta(seconds=settings.facts_refresh_interval_seconds),
    },
    "check-all-machine-updates": {
        "task": "app.tasks.jobs.check_all_machine_updates",
        "schedule": timedelta(seconds=settings.facts_refresh_interval_seconds),
    },
    # Cron expressions are minute-grained anyway, so a fixed per-minute tick
    # (rather than a configurable interval) is the natural fit for the
    # scheduler.
    "run-due-scheduled-tasks": {
        "task": "app.scheduling.jobs.run_due_scheduled_tasks",
        "schedule": crontab(),
    },
    # Once a day is plenty for a retention sweep — only *how many days to
    # keep* is configurable (Settings page), not this cadence.
    "purge-old-audit-log-entries": {
        "task": "app.tasks.jobs.purge_old_audit_log_entries",
        "schedule": crontab(hour=3, minute=0),
    },
    # Snapshot before purge, both once daily — order between them doesn't
    # matter (a purge only ever removes rows older than the retention window,
    # never today's brand-new one).
    "record-fleet-snapshot": {
        "task": "app.tasks.jobs.record_fleet_snapshot",
        "schedule": crontab(hour=2, minute=0),
    },
    "purge-old-fleet-snapshots": {
        "task": "app.tasks.jobs.purge_old_fleet_snapshots",
        "schedule": crontab(hour=3, minute=5),
    },
    "purge-old-machine-update-runs": {
        "task": "app.tasks.jobs.purge_old_machine_update_runs",
        "schedule": crontab(hour=3, minute=10),
    },
}


@worker_process_init.connect
def _init_worker_process(**kwargs: Any) -> None:
    """Per-forked-child setup. See this module's docstring for the full why.

    Runs in each `prefork` child right after the fork, before it takes its
    first task.
    """
    from app.db import session as db_session
    from app.scheduling.builtin_actions import register_builtin_actions

    child_settings = get_settings()

    # Rebuild, don't reuse: whatever engine this child inherited from the
    # parent is pointing at sockets the parent (and every sibling) also
    # holds. `dispose()` is deliberately NOT called on the inherited engine
    # — that would close those shared sockets for everyone.
    #
    # `poolclass=NullPool` matters just as much as rebuilding it: every task
    # below runs its own `asyncio.run(...)` (see app/tasks/jobs.py), which is
    # a brand new event loop each time. A real connection pool would hand a
    # later task a connection opened on an earlier task's (by then closed)
    # loop, and asyncpg blows up with "attached to a different loop" the
    # moment that connection is used — this bit real deployments as
    # intermittent failures on update/refresh/test-connection tasks. NullPool
    # opens a fresh connection per checkout and closes it on checkin, so a
    # connection never outlives the event loop that created it.
    db_session.engine = create_async_engine(
        child_settings.database_url,
        poolclass=NullPool,
        echo=False,
    )
    db_session.AsyncSessionLocal = async_sessionmaker(
        bind=db_session.engine,
        expire_on_commit=False,
        autoflush=False,
    )

    # Populates app.scheduling.actions' registry — must happen before this
    # process evaluates or runs a scheduled task. Idempotent (it returns
    # early if already registered), so doing it here as well as at import
    # time in app.main is harmless.
    register_builtin_actions()

    logger.info("Celery worker process initialised (fresh DB engine).")
