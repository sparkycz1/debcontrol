"""Live "next runs" preview for the schedule form, and its API twin."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.scheduling.cron import next_runs
from tests.test_api_v1_extended import _api_token


def test_next_runs_lists_upcoming_utc_times() -> None:
    after = datetime(2026, 9, 25, 12, 0, tzinfo=UTC)
    runs = next_runs("0 3 * * *", count=3, after=after)
    assert [r.isoformat() for r in runs] == [
        "2026-09-26T03:00:00+00:00",
        "2026-09-27T03:00:00+00:00",
        "2026-09-28T03:00:00+00:00",
    ]


def test_next_runs_rejects_invalid_expression() -> None:
    with pytest.raises(ValueError):
        next_runs("not a cron")


async def test_preview_fragment(client):
    ok = await client.get("/scheduling/cron-preview", params={"cron_expression": "0 3 * * *"})
    assert ok.status_code == 200
    assert "03:00 UTC" in ok.text
    bad = await client.get("/scheduling/cron-preview", params={"cron_expression": "nope"})
    assert "Not a valid cron expression" in bad.text
    empty = await client.get("/scheduling/cron-preview")
    assert "UTC" not in empty.text


async def test_form_wires_the_preview(client):
    page = await client.get("/scheduling/new")
    assert 'hx-get="/scheduling/cron-preview"' in page.text
    assert 'id="cron-preview"' in page.text


async def test_preview_api(client):
    headers = await _api_token(client)
    ok = await client.get(
        "/api/v1/scheduling/cron-preview", params={"expression": "*/15 * * * *", "count": 2},
        headers=headers,
    )
    assert ok.status_code == 200
    assert len(ok.json()["next_runs"]) == 2
    bad = await client.get(
        "/api/v1/scheduling/cron-preview", params={"expression": "x"}, headers=headers
    )
    assert bad.status_code == 422
