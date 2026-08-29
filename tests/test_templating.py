from __future__ import annotations

from app.web.templating import format_uptime


def test_format_uptime_none():
    assert format_uptime(None) == "—"


def test_format_uptime_seconds_only():
    assert format_uptime(45) == "0m"


def test_format_uptime_minutes():
    assert format_uptime(60 * 5) == "5m"


def test_format_uptime_hours_and_minutes():
    assert format_uptime(3661) == "1h 1m"


def test_format_uptime_days_hours_minutes():
    seconds = 2 * 86400 + 3 * 3600 + 4 * 60 + 5
    assert format_uptime(seconds) == "2d 3h 4m"
