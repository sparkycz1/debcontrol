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

import asyncio
import logging
import sys
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

# Built-in fallback for the four interval settings below — used only if the
# database isn't reachable yet at process start (e.g. the very first boot,
# before `alembic upgrade head` has run against a brand new Postgres).
# Matches `AppSettings`'s own column defaults (app/db/models/app_settings.py).
_INTERVAL_SETTING_DEFAULTS: dict[str, int] = {
    "reachability_check_interval_seconds": 60,
    "facts_refresh_interval_seconds": 3600,
    "monitoring_interval_seconds": 120,
    "notification_condition_check_interval_seconds": 60,
}


def _bootstrap_interval_settings() -> dict[str, int]:
    """One-time, synchronous-from-the-caller's-perspective read of the three
    Beat-schedule intervals from `AppSettings`, for the `beat_schedule`
    dict literal below — a Celery schedule has to be a plain value computed
    once at import time, not something re-read from the database on every
    tick, so this is the one place those settings are still read "once at
    process start, restart to pick up a change," same as when they were
    environment variables.

    This module is imported identically by the web app, every Celery
    worker, and Celery Beat (see `app.tasks.jobs`'s import of `celery_app`)
    — but only Beat's own schedule actually depends on these three values,
    so only the `celery ... beat` process pays for the database round trip
    this needs; every other import (the web app, a worker, `alembic`, the
    test suite collecting `app.main`) gets the built-in defaults
    immediately with no I/O at all, matching this app's "tests never touch
    a real Postgres" contract. Detected via `sys.argv` rather than a
    dedicated environment variable, since that's already exactly how
    Celery itself is told which role to run as.

    Uses its own throwaway engine (`NullPool`, torn down again immediately)
    rather than `app.db.session`'s module-level one: this runs via
    `asyncio.run()` in the *parent* process before any worker child forks
    (see `_init_worker_process`'s own docstring for why a pooled connection
    and `asyncio.run()`'s own fresh event loop each call don't mix), and
    before that module's own engine may even be usable here.

    Falls back to `_INTERVAL_SETTING_DEFAULTS` — never raises — if the
    database isn't reachable yet, so a fresh, not-yet-migrated instance's
    `beat` container still starts instead of crash-looping; the real
    configured values take effect on the next restart once the database is
    up.
    """
    if "beat" not in sys.argv:
        return dict(_INTERVAL_SETTING_DEFAULTS)

    async def _fetch() -> dict[str, int]:
        from app.core.app_settings import get_or_create_app_settings

        engine = create_async_engine(settings.database_url, poolclass=NullPool, echo=False)
        try:
            session_factory = async_sessionmaker(
                bind=engine, expire_on_commit=False, autoflush=False
            )
            async with session_factory() as db:
                app_settings = await get_or_create_app_settings(db)
                return {
                    key: getattr(app_settings, key) for key in _INTERVAL_SETTING_DEFAULTS
                }
        finally:
            await engine.dispose()

    try:
        return asyncio.run(_fetch())
    except Exception:
        logger.warning(
            "Could not read background-check intervals from the database at startup "
            "(using the built-in defaults until the next restart) — is the database "
            "reachable and migrated yet?",
            exc_info=True,
        )
        return dict(_INTERVAL_SETTING_DEFAULTS)

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
# The three fleet sweeps run on a configurable interval taken from
# `AppSettings` (app/db/models/app_settings.py — moved here from environment
# variables), which is why they are `timedelta(...)` schedules rather than
# crontabs.
#
# NOTE: these intervals are read once, here, at process start (worker or
# beat) — the same "restart to pick up a change" contract they had back when
# they were environment variables, just now sourced from the database
# instead of `.env`. See `_bootstrap_interval_settings` below for how that
# one-off read happens and what it falls back to if the database isn't
# reachable yet.
#
# Beat has no persisted "last run" on a fresh start, so each entry fires once
# shortly after startup on its own — which is exactly the behaviour the old
# queue needed a hand-written "kick off the first sweep" hook to get.
_interval_settings = _bootstrap_interval_settings()
celery_app.conf.beat_schedule = {
    "ping-all-machines": {
        "task": "app.tasks.jobs.ping_all_machines",
        "schedule": timedelta(seconds=_interval_settings["reachability_check_interval_seconds"]),
    },
    "refresh-all-machine-facts": {
        "task": "app.tasks.jobs.refresh_all_machine_facts",
        "schedule": timedelta(seconds=_interval_settings["facts_refresh_interval_seconds"]),
    },
    "refresh-all-machine-packages": {
        "task": "app.tasks.jobs.refresh_all_machine_packages",
        "schedule": timedelta(seconds=_interval_settings["facts_refresh_interval_seconds"]),
    },
    "check-all-machine-updates": {
        "task": "app.tasks.jobs.check_all_machine_updates",
        "schedule": timedelta(seconds=_interval_settings["facts_refresh_interval_seconds"]),
    },
    "refresh-all-machine-services": {
        "task": "app.tasks.jobs.refresh_all_machine_services",
        "schedule": timedelta(seconds=_interval_settings["facts_refresh_interval_seconds"]),
    },
    # Was on-demand only (right after a host key was first trusted, or an
    # explicit "Re-check"/"Run initial setup" click) — a requirement that
    # got un-set later (ncurses-term removed by `autoremove`, a sudoers
    # grant edited away) would never surface on its own. Same cadence as
    # the other fleet sweeps above; see app.tasks.jobs._refresh_all_machine_readiness.
    "refresh-all-machine-readiness": {
        "task": "app.tasks.jobs.refresh_all_machine_readiness",
        "schedule": timedelta(seconds=_interval_settings["facts_refresh_interval_seconds"]),
    },
    "monitor-all-machines": {
        "task": "app.tasks.jobs.monitor_all_machines",
        "schedule": timedelta(seconds=_interval_settings["monitoring_interval_seconds"]),
    },
    # Re-evaluates every condition-based notification rule (CPU/RAM/disk/
    # facts thresholds — see app.db.models.notification_condition) against
    # the fleet's latest facts/monitoring data. Runs after the sweeps above
    # write their results, so it reads already-fresh rows rather than
    # triggering new SSH work of its own.
    "evaluate-notification-conditions": {
        "task": "app.tasks.jobs.evaluate_notification_conditions",
        "schedule": timedelta(
            seconds=_interval_settings["notification_condition_check_interval_seconds"]
        ),
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
    "purge-old-monitoring-samples": {
        "task": "app.tasks.jobs.purge_old_monitoring_samples",
        "schedule": crontab(hour=3, minute=15),
    },
    # Thins out (not purges — see the task's own docstring) monitoring
    # samples old enough that a chart only ever renders them bucketed
    # anyway. Runs shortly before the purge above so a sample newly past
    # the retention window on the same night is deleted outright rather
    # than downsampled first for no benefit.
    "downsample-old-monitoring-samples": {
        "task": "app.tasks.jobs.downsample_old_monitoring_samples",
        "schedule": crontab(hour=3, minute=12),
    },
    # Off by default (AppSettings.fleet_summary_frequency) — this tick is a
    # cheap no-op check unless an admin opted in. Runs once a day regardless
    # of whether the chosen frequency is "daily" or "weekly": the task
    # itself decides whether today's tick is actually due — see
    # app.tasks.ai_jobs._fleet_summary_due. A later hour than the retention
    # sweeps above so a same-day fleet snapshot/purge has already run.
    "generate-fleet-summary": {
        "task": "app.tasks.ai_jobs.generate_fleet_summary",
        "schedule": crontab(hour=6, minute=0),
    },
    "purge-old-notification-logs": {
        "task": "app.tasks.jobs.purge_old_notification_logs",
        "schedule": crontab(hour=3, minute=25),
    },
    "purge-old-fleet-summaries": {
        "task": "app.tasks.ai_jobs.purge_old_fleet_summaries",
        "schedule": crontab(hour=3, minute=20),
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
