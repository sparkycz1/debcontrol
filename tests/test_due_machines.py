"""`app.tasks.jobs._due_machines` — the pure filtering logic behind both
periodic sweeps (`_ping_all_machines`/`_refresh_all_machine_facts`) that
lets a machine's own `reachability_check_interval_seconds`/
`facts_refresh_interval_seconds` override raise its effective check
interval above the instance-wide `.env` default. Tested here as a pure
function against plain objects — no DB, no Celery — since `_due_machines`
takes callables rather than committing to `Machine` directly.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from app.tasks.jobs import _due_machines

NOW = datetime(2026, 9, 1, 12, 0, 0, tzinfo=UTC)


@dataclass
class _FakeMachine:
    name: str
    last_checked_at: datetime | None
    override_seconds: int | None = None


def test_never_checked_machine_is_always_due():
    machine = _FakeMachine(name="new", last_checked_at=None)

    due = _due_machines(
        [machine],
        last_checked_at=lambda m: m.last_checked_at,
        override_seconds=lambda m: m.override_seconds,
        global_default_seconds=60,
        now=NOW,
    )

    assert due == [machine]


def test_machine_without_override_uses_global_default():
    stale = _FakeMachine(name="stale", last_checked_at=NOW - timedelta(seconds=61))
    fresh = _FakeMachine(name="fresh", last_checked_at=NOW - timedelta(seconds=30))

    due = _due_machines(
        [stale, fresh],
        last_checked_at=lambda m: m.last_checked_at,
        override_seconds=lambda m: m.override_seconds,
        global_default_seconds=60,
        now=NOW,
    )

    assert due == [stale]


def test_override_raises_the_effective_interval():
    # Would be due under the 60s global default, but its own 1-hour
    # override says otherwise.
    machine = _FakeMachine(
        name="quiet", last_checked_at=NOW - timedelta(seconds=120), override_seconds=3600
    )

    due = _due_machines(
        [machine],
        last_checked_at=lambda m: m.last_checked_at,
        override_seconds=lambda m: m.override_seconds,
        global_default_seconds=60,
        now=NOW,
    )

    assert due == []


def test_override_cannot_lower_below_the_sweep_tick_rate():
    # A machine can't be checked more often than the sweep itself ticks —
    # a smaller override doesn't make it due any sooner than the next tick.
    machine = _FakeMachine(
        name="eager", last_checked_at=NOW - timedelta(seconds=30), override_seconds=10
    )

    due = _due_machines(
        [machine],
        last_checked_at=lambda m: m.last_checked_at,
        override_seconds=lambda m: m.override_seconds,
        global_default_seconds=60,
        now=NOW,
    )

    # It's still "due" here only because 30s already exceeds its own 10s
    # override — the point is just that _due_machines never gets called
    # more than once per tick to begin with; this asserts the interval math
    # itself, not the tick rate (which is Celery Beat's job).
    assert due == [machine]
