"""Each account's own Dashboard (`app.services.dashboard_layout`): order
and hidden sections, on the page and in the REST API."""

from __future__ import annotations

import re
from typing import Any

from httpx2 import AsyncClient
from sqlalchemy import select

from app.db.models.user import User
from app.services import dashboard_layout
from tests.test_homelab_round import _add_machine
from tests.test_update_history import _api_token


def test_a_stored_layout_survives_added_and_removed_sections() -> None:
    layout = dashboard_layout.resolve(
        {"order": ["fleet", "gone", "machines", "fleet"], "hidden": ["trends", "gone"]}
    )

    # Known keys in the stored order, then every section it did not mention.
    assert layout.order == ("fleet", "machines", "summary", "trends", "scheduling", "activity")
    assert layout.hidden == frozenset({"trends"})
    assert "trends" not in layout.visible and layout.visible[0] == "fleet"
    assert dashboard_layout.resolve(None) == dashboard_layout.DEFAULT
    assert dashboard_layout.resolve("nonsense") == dashboard_layout.DEFAULT


def test_moving_and_hiding() -> None:
    layout = dashboard_layout.DEFAULT

    moved = dashboard_layout.move(layout, "fleet", up=True)
    at_top = dashboard_layout.move(layout, "machines", up=True)
    hidden = dashboard_layout.set_hidden(moved, "summary", hidden=True)

    assert moved.order[-2:] == ("fleet", "activity")
    assert at_top == layout
    assert hidden.hidden == frozenset({"summary"})
    assert dashboard_layout.to_store(layout) is None
    assert dashboard_layout.to_store(hidden) == {
        "order": list(moved.order),
        "hidden": ["summary"],
    }


async def test_arranging_the_dashboard(client: AsyncClient, db_session_factory: Any) -> None:
    await _add_machine(db_session_factory)
    page = await client.get("/dashboard")
    match = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    assert match is not None
    csrf = match.group(1)

    def sections(text: str) -> str:
        """The page below the "Arrange this page" box."""
        after = text[text.index('class="dashboard-arrange"') :]
        return after[after.index("</details>") :]

    def position(text: str, marker: str) -> int:
        return sections(text).index(marker)

    assert position(page.text, 'id="fleet"') > position(page.text, "/audit")
    for action, section in (
        ("up", "fleet"),
        ("up", "fleet"),
        ("up", "fleet"),
        ("up", "fleet"),
        ("up", "fleet"),
        ("hide", "activity"),
    ):
        response = await client.post(
            "/dashboard/layout",
            data={"csrf_token": csrf, "action": action, "section": section},
            follow_redirects=False,
        )
        assert response.headers["location"] == "/dashboard?arrange=1"
    arranged = await client.get("/dashboard?arrange=1")
    unknown = await client.post(
        "/dashboard/layout", data={"csrf_token": csrf, "action": "up", "section": "nope"}
    )

    body = sections(arranged.text)
    assert body.index('id="fleet"') < body.index("stat-card")
    # The activity section is gone from the page, but still listed to bring back.
    assert 'href="/audit"' not in body
    assert "<details class=\"dashboard-arrange\" open>" in arranged.text
    assert 'value="show"' in arranged.text and 'value="reset"' in arranged.text
    assert unknown.status_code == 400
    async with db_session_factory() as db:
        user = (await db.execute(select(User))).scalars().first()
        assert user is not None and user.dashboard_layout is not None
        assert user.dashboard_layout["order"][0] == "fleet"

    await client.post("/dashboard/layout", data={"csrf_token": csrf, "action": "reset"})
    async with db_session_factory() as db:
        user = (await db.execute(select(User))).scalars().first()
        assert user is not None and user.dashboard_layout is None


async def test_dashboard_layout_api(client: AsyncClient) -> None:
    headers = await _api_token(client)
    url = "/api/v1/account/dashboard-layout"

    default = (await client.get(url, headers=headers)).json()
    saved = await client.put(
        url, headers=headers, json={"order": ["fleet", "machines"], "hidden": ["trends"]}
    )
    bad = await client.put(url, headers=headers, json={"order": ["nope"]})
    reset = await client.put(url, headers=headers, json={})

    assert default["order"] == default["sections"] and default["hidden"] == []
    assert saved.status_code == 200
    assert saved.json()["order"][:2] == ["fleet", "machines"]
    assert saved.json()["hidden"] == ["trends"]
    assert bad.status_code == 422
    assert reset.json()["order"] == reset.json()["sections"]
