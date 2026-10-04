"""A chart page's time window: one of the presets, or a custom from-to
stretch (`app.services.monitoring_history.TimeWindow`,
`app.web.time_window`)."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import parse_qs

from app.db.models.endpoint_check import EndpointCheck
from app.db.models.endpoint_check_result import EndpointCheckResult
from app.db.models.machine import AuthMethod, Machine
from app.db.models.machine_monitoring_sample import MachineMonitoringSample
from app.services import monitoring_history
from app.web.time_window import window_from_query, window_query
from tests.test_api_v1_extended import _api_token

NOW = datetime(2026, 10, 4, 12, 0, tzinfo=UTC)


def test_a_preset_ends_now_and_an_unknown_key_falls_back() -> None:
    window = monitoring_history.resolve_window("7d", now=NOW)
    assert (window.range_key, window.since, window.until) == ("7d", NOW - timedelta(days=7), None)
    assert not window.is_custom and window.axis_format == "%d.%m."
    assert monitoring_history.resolve_window("nonsense", now=NOW).range_key == "1h"


def test_a_custom_window_is_ordered_and_clamped() -> None:
    start, end = NOW - timedelta(hours=6), NOW - timedelta(hours=2)
    window = monitoring_history.resolve_window("7d", start, end, now=NOW)
    assert window.is_custom and (window.since, window.until) == (start, end)
    assert window.axis_format == "%H:%M"

    # Given the wrong way round, ending in the future, or absurdly short.
    swapped = monitoring_history.resolve_window("1h", end, start, now=NOW)
    assert (swapped.since, swapped.until) == (start, end)
    future = monitoring_history.resolve_window("1h", start, NOW + timedelta(days=1), now=NOW)
    assert future.until == NOW
    tiny = monitoring_history.resolve_window("1h", end, end, now=NOW)
    assert tiny.until is not None
    assert tiny.until - tiny.since == monitoring_history.MIN_CUSTOM_SPAN
    # Only one end given: not a custom window.
    assert not monitoring_history.resolve_window("24h", start, None, now=NOW).is_custom


def test_the_query_string_round_trips() -> None:
    assert window_query(window_from_query("24h")) == "range_key=24h"
    assert not window_from_query("24h", "garbage", "2026-10-01T10:00").is_custom

    custom = window_from_query("", "2026-10-01T08:00:00+00:00", "2026-10-01T10:00:00Z")
    assert custom.is_custom
    query = parse_qs(window_query(custom))
    again = window_from_query("", query["start"][0], query["end"][0])
    assert (again.since, again.until) == (custom.since, custom.until)


async def _machine_with_samples(db_session_factory: Any) -> Any:
    async with db_session_factory() as db:
        machine = Machine(
            name="web1",
            ip_address="10.0.0.1",
            port=22,
            username="root",
            auth_method=AuthMethod.PASSWORD,
        )
        db.add(machine)
        await db.flush()
        base = datetime.now(UTC).replace(microsecond=0) - timedelta(hours=10)
        for hour in range(10):
            db.add(
                MachineMonitoringSample(
                    machine_id=machine.id,
                    sampled_at=base + timedelta(hours=hour),
                    cpu_percent=float(hour),
                )
            )
        machine.monitoring_updated_at = base + timedelta(hours=9)
        await db.commit()
        return machine.id, base


async def test_monitoring_page_shows_only_the_custom_window(
    client: Any, db_session_factory: Any
) -> None:
    machine_id, base = await _machine_with_samples(db_session_factory)
    start, end = base + timedelta(hours=2), base + timedelta(hours=5)

    page = await client.get(
        f"/machines/{machine_id}/monitoring",
        params={"start": start.isoformat(), "end": end.isoformat()},
    )
    assert page.status_code == 200
    assert 'name="start"' in page.text and "data-chart-zoom" in page.text
    charts = [
        json.loads(raw.replace("&#34;", '"'))
        for raw in re.findall(r"data-chart='([^']+)'", page.text)
    ]
    cpu = next(c for c in charts if c["s"] and c["s"][0]["v"] == [2.0, 3.0, 4.0, 5.0])
    assert cpu["e"] == [int((base + timedelta(hours=h)).timestamp()) for h in (2, 3, 4, 5)]
    # "Refresh now" comes back to the same window.
    assert "monitoring/refresh?start=" in page.text

    preset = await client.get(f"/machines/{machine_id}/monitoring", params={"range_key": "24h"})
    assert "monitoring/refresh?range_key=24h" in preset.text


async def test_api_takes_a_custom_window(client: Any, db_session_factory: Any) -> None:
    machine_id, base = await _machine_with_samples(db_session_factory)
    async with db_session_factory() as db:
        check = EndpointCheck(name="shop", kind="http", target="https://shop.example.com")
        db.add(check)
        await db.flush()
        for hour in range(10):
            db.add(
                EndpointCheckResult(
                    check_id=check.id, checked_at=base + timedelta(hours=hour), ok=True
                )
            )
        await db.commit()
        check_id = check.id
    headers = await _api_token(client)
    params = {
        "start": (base + timedelta(hours=2)).isoformat(),
        "end": (base + timedelta(hours=5)).isoformat(),
    }

    machine = await client.get(
        f"/api/v1/machines/{machine_id}/monitoring", params=params, headers=headers
    )
    assert machine.status_code == 200
    body = machine.json()
    assert body["range_key"] == "custom" and body["until"] is not None
    assert body["monitoring"]["sample_count"] == 4

    check_history = await client.get(
        f"/api/v1/checks/{check_id}/history", params=params, headers=headers
    )
    assert check_history.json()["sample_count"] == 4
    assert (
        await client.get(f"/api/v1/checks/{check_id}/history", headers=headers)
    ).status_code == 200

    page = await client.get(f"/checks/{check_id}", params=params)
    assert page.status_code == 200 and 'name="end"' in page.text
