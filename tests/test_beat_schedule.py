"""Regression guard for a real bug found in a sister project (HoneyHive):
`celery_app.py`'s `beat_schedule` ended up with only 3 of the ~14 periodic
entries it should have had, after someone rewrote the file and simply
forgot most of them — no reachability/facts/packages/services/readiness/
update-check/monitoring sweep, and no scheduling tick, ever fired on its
own again. Every one of those tasks still worked fine when triggered
manually (a "Refresh now" button, `.delay()` from a route); only the
*automatic* cadence was silently dead. Not caught by that project's own
test suite for the same reason it wouldn't be caught by this one:
`tests/conftest.py` monkeypatches `Task.apply_async` itself, so no test
here ever touches a real Beat/worker/broker pair — `beat_schedule` and
`include=` are just Python data structures nothing else exercises.

debcontrol doesn't have this bug today (verified by hand against
`app/tasks/celery_app.py` when this test was added) — this is the
preventive test that stops it from *becoming* true unnoticed, the same
role `test_static_assets_exist.py` plays for that sister project's other
bug.
"""

from __future__ import annotations

# `celery_app.py`'s `include=[...]` is a *lazy* import Celery only follows
# itself on a real worker/beat startup (see that module's own docstring —
# it has to be lazy to avoid a circular import) — plain `import
# app.tasks.celery_app` alone never populates `celery_app.tasks`. These
# three explicit imports are what `test_every_beat_schedule_task_is_
# actually_registered` below actually needs; without them that test's
# result would depend on which *other* test modules pytest happened to
# have already imported first, which is exactly the kind of accidental,
# order-dependent pass this test exists to not be.
import app.scheduling.jobs
import app.tasks.ai_jobs
import app.tasks.jobs  # noqa: F401
from app.tasks.celery_app import celery_app

# Every task this app expects to fire on its own, on a schedule, with no
# human clicking a button — not just "beat_schedule has *something* in
# it," but this exact set. Update this list in the same change that adds
# or removes a periodic sweep (see app/tasks/celery_app.py's own
# beat_schedule for what each one does and why its cadence is what it is).
_EXPECTED_PERIODIC_TASKS = {
    "app.tasks.jobs.ping_all_machines",
    "app.tasks.jobs.refresh_all_machine_facts",
    "app.tasks.jobs.refresh_all_machine_packages",
    "app.tasks.jobs.check_all_machine_updates",
    "app.tasks.jobs.refresh_all_machine_services",
    "app.tasks.jobs.refresh_all_machine_readiness",
    "app.tasks.jobs.monitor_all_machines",
    "app.scheduling.jobs.run_due_scheduled_tasks",
    "app.tasks.jobs.purge_old_audit_log_entries",
    "app.tasks.jobs.record_fleet_snapshot",
    "app.tasks.jobs.purge_old_fleet_snapshots",
    "app.tasks.jobs.purge_old_machine_update_runs",
    "app.tasks.jobs.purge_old_monitoring_samples",
    "app.tasks.ai_jobs.generate_fleet_summary",
    "app.tasks.ai_jobs.purge_old_fleet_summaries",
    "app.tasks.jobs.run_due_app_backup",
}


def test_beat_schedule_has_every_expected_periodic_task() -> None:
    scheduled = {entry["task"] for entry in celery_app.conf.beat_schedule.values()}
    missing = _EXPECTED_PERIODIC_TASKS - scheduled
    assert not missing, (
        "beat_schedule is missing periodic task(s) that should fire "
        f"automatically, not just on manual trigger: {sorted(missing)}"
    )


def test_celery_app_includes_every_module_with_a_periodic_task() -> None:
    """Every module whose tasks show up in `beat_schedule` must also be in
    `include=` — a standalone `worker`/`beat` process only ever imports
    what's listed there (unlike the web process, which imports everything
    transitively through its routes), so a task from a module missing here
    gets rejected as unregistered the moment Beat/a route tries to enqueue
    it. Silently: the message is just NACKed, no exception anywhere a
    human would see it."""
    included = set(celery_app.conf.include)
    modules_with_periodic_tasks = {
        task_name.rsplit(".", 1)[0] for task_name in _EXPECTED_PERIODIC_TASKS
    }
    missing = modules_with_periodic_tasks - included
    assert not missing, f"Not in celery_app's include=[...]: {sorted(missing)}"


def test_every_beat_schedule_task_is_actually_registered() -> None:
    """The flip side of the two checks above: every task name
    `beat_schedule` refers to must correspond to a real `@celery_app.task`
    somewhere this process has imported — a typo'd task name in
    `beat_schedule` is exactly as silent a failure (Beat fires it, the
    broker gets a message for a name nothing ever registered) as a missing
    `include=` entry."""
    registered = set(celery_app.tasks.keys())
    scheduled = {entry["task"] for entry in celery_app.conf.beat_schedule.values()}
    missing = scheduled - registered
    assert not missing, f"beat_schedule refers to unregistered task(s): {sorted(missing)}"
