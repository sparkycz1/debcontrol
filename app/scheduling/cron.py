"""Standard 5-field cron expression handling for scheduled tasks.

A schedule is read in its task's own time zone (`ScheduledTask.timezone`,
an IANA name such as `Europe/Prague`) — "0 3 * * *" means 03:00 there,
summer and winter alike. A task without one (every task saved before
0.78.0) keeps running in UTC, exactly as before. Every computed time is
returned in UTC, like every other timestamp this app stores.

Across a daylight-saving change croniter follows the wall clock: a time
that doesn't exist that night (02:30 when clocks jump 02:00 → 03:00) runs
at the next valid minute, and one that happens twice runs once.
"""

from __future__ import annotations

from datetime import UTC, datetime

from croniter import CroniterBadCronError, croniter

from app.core.timezones import zone


def validate_cron_expression(expression: str) -> None:
    """Raise ValueError with a human-readable message if `expression` isn't
    a valid 5-field cron expression."""
    if not croniter.is_valid(expression):
        raise ValueError(
            f'"{expression}" is not a valid cron expression — expected 5 space-separated '
            "fields (minute hour day-of-month month day-of-week), e.g. \"0 3 * * *\" for "
            "03:00 every day."
        )


def _iterator(expression: str, after: datetime | None, timezone: str | None) -> croniter:
    base = after or datetime.now(UTC)
    if base.tzinfo is None:
        base = base.replace(tzinfo=UTC)
    return croniter(expression, base.astimezone(zone(timezone or "UTC")))


def _as_utc(value: datetime) -> datetime:
    return value.astimezone(UTC)


def compute_next_run(
    expression: str, after: datetime | None = None, timezone: str | None = None
) -> datetime:
    """The next time `expression` fires in `timezone` (default UTC),
    strictly after `after` (defaults to now), as a UTC datetime."""
    try:
        return _as_utc(_iterator(expression, after, timezone).get_next(datetime))
    except CroniterBadCronError as exc:
        raise ValueError(str(exc)) from exc


# How many upcoming runs the schedule form previews.
PREVIEW_RUN_COUNT = 5


def next_runs(
    expression: str,
    count: int = PREVIEW_RUN_COUNT,
    after: datetime | None = None,
    timezone: str | None = None,
) -> list[datetime]:
    """The next `count` times `expression` fires in `timezone` (default
    UTC), strictly after `after` (defaults to now), as UTC datetimes — the
    schedule form's live preview and `GET /api/v1/scheduling/cron-preview`.
    Raises `ValueError` for an invalid expression, same message as
    `validate_cron_expression`."""
    validate_cron_expression(expression)
    iterator = _iterator(expression, after, timezone)
    try:
        return [_as_utc(iterator.get_next(datetime)) for _ in range(count)]
    except CroniterBadCronError as exc:
        raise ValueError(str(exc)) from exc
