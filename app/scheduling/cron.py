"""Standard 5-field cron expression handling for scheduled tasks.

Schedules are interpreted in UTC, same as every other timestamp in this app —
there's no per-schedule timezone setting (deliberately, to keep this simple;
add one later if it turns out to matter).
"""

from __future__ import annotations

from datetime import UTC, datetime

from croniter import CroniterBadCronError, croniter


def validate_cron_expression(expression: str) -> None:
    """Raise ValueError with a human-readable message if `expression` isn't
    a valid 5-field cron expression."""
    if not croniter.is_valid(expression):
        raise ValueError(
            f'"{expression}" is not a valid cron expression — expected 5 space-separated '
            "fields (minute hour day-of-month month day-of-week), e.g. \"0 3 * * *\" for "
            "03:00 UTC every day."
        )


def compute_next_run(expression: str, after: datetime | None = None) -> datetime:
    """The next UTC time `expression` fires, strictly after `after`
    (defaults to now)."""
    base = after or datetime.now(UTC)
    try:
        return croniter(expression, base).get_next(datetime)
    except CroniterBadCronError as exc:
        raise ValueError(str(exc)) from exc
