"""app.web.templating.local_time — rendering stored (UTC) datetimes in the
configured `TZ` (Settings.tz) instead of hardcoded UTC.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime

import pytest

from app.core.config import get_settings
from app.web.templating import format_uptime, local_time


def test_format_uptime_none() -> None:
    assert format_uptime(None) == "—"


def test_format_uptime_seconds_only() -> None:
    assert format_uptime(45) == "0m"


def test_format_uptime_minutes() -> None:
    assert format_uptime(60 * 5) == "5m"


def test_format_uptime_hours_and_minutes() -> None:
    assert format_uptime(3661) == "1h 1m"


def test_format_uptime_days_hours_minutes() -> None:
    seconds = 2 * 86400 + 3 * 3600 + 4 * 60 + 5
    assert format_uptime(seconds) == "2d 3h 4m"


@pytest.fixture(autouse=True)
def _clear_settings_cache() -> Iterator[None]:
    """`get_settings()` is `lru_cache`d — clear it around each test so a
    `monkeypatch.setenv("TZ", ...)` actually takes effect."""
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def test_none_renders_as_em_dash() -> None:
    assert local_time(None) == "—"


def test_defaults_to_utc_when_tz_is_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TZ", raising=False)
    value = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)
    assert local_time(value, "%Y-%m-%d %H:%M %Z") == "2026-01-15 12:00 UTC"


def test_naive_datetime_is_treated_as_utc(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TZ", raising=False)
    naive = datetime(2026, 1, 15, 12, 0, 0)
    assert local_time(naive, "%Y-%m-%d %H:%M %Z") == "2026-01-15 12:00 UTC"


def test_converts_to_the_configured_timezone(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TZ", "Europe/Prague")
    # Winter — CET, UTC+1.
    value = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)
    assert local_time(value, "%Y-%m-%d %H:%M %Z") == "2026-01-15 13:00 CET"


def test_unrecognized_timezone_falls_back_to_utc(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TZ", "Not/A_Real_Zone")
    value = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)
    assert local_time(value, "%Y-%m-%d %H:%M %Z") == "2026-01-15 12:00 UTC"


def test_date_only_format_has_no_zone_suffix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TZ", "Europe/Prague")
    value = datetime(2026, 1, 15, 23, 30, 0, tzinfo=UTC)
    # 23:30 UTC in January is already the 16th in Europe/Prague (UTC+1).
    assert local_time(value, "%Y-%m-%d") == "2026-01-16"
