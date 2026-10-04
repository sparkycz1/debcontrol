"""The header search box (`app.services.global_search`): what it finds,
and that it shows an account only what that account could open anyway."""

from __future__ import annotations

from typing import Any

from app.db.models.endpoint_check import EndpointCheck
from app.db.models.machine import AuthMethod, Machine
from app.db.models.machine_group import MachineGroup
from app.db.models.notification_rule import NotificationEventType, NotificationRule
from app.db.models.role import Permission
from app.db.models.scheduled_task import ScheduledTask, ScheduleTargetType
from tests.test_api_v1_extended import _api_token


async def _seed(db_session_factory: Any) -> None:
    async with db_session_factory() as db:
        group = MachineGroup(name="Atlas web")
        db.add(group)
        await db.flush()
        db.add_all(
            [
                Machine(
                    name="atlas-web1",
                    ip_address="10.0.0.1",
                    port=22,
                    username="root",
                    auth_method=AuthMethod.PASSWORD,
                    group_id=group.id,
                ),
                Machine(
                    name="mail1",
                    ip_address="10.0.0.2",
                    port=22,
                    username="root",
                    auth_method=AuthMethod.PASSWORD,
                ),
                EndpointCheck(name="Atlas shop", kind="http", target="https://shop.example.com"),
                ScheduledTask(
                    name="Atlas nightly update",
                    action="system_update",
                    target_type=ScheduleTargetType.ALL_MACHINES,
                    cron_expression="0 3 * * *",
                ),
                NotificationRule(
                    name="Atlas outages",
                    enabled=True,
                    event_types=[NotificationEventType.MACHINE_UNREACHABLE.value],
                ),
            ]
        )
        await db.commit()


async def test_search_page_groups_matches_by_kind(client: Any, db_session_factory: Any) -> None:
    await _seed(db_session_factory)

    page = await client.get("/search", params={"q": "atlas"})
    assert page.status_code == 200
    for expected in (
        "atlas-web1",
        "Atlas web",
        "Atlas shop",
        "Atlas nightly update",
        "Atlas outages",
    ):
        assert expected in page.text
    assert "mail1" not in page.text

    # By address, and the page with nothing typed or too little.
    assert "mail1" in (await client.get("/search", params={"q": "10.0.0.2"})).text
    assert (await client.get("/search")).status_code == 200
    short = await client.get("/search", params={"q": "a"})
    assert "atlas-web1" not in short.text

    nothing = await client.get("/search", params={"q": "zzz-nope"})
    assert "atlas-web1" not in nothing.text and "zzz-nope" in nothing.text


async def test_every_page_has_the_search_box(client: Any) -> None:
    page = await client.get("/dashboard")
    assert 'action="/search"' in page.text and "data-global-search" in page.text


async def test_a_wildcard_in_the_query_is_taken_literally(
    client: Any, db_session_factory: Any
) -> None:
    await _seed(db_session_factory)
    page = await client.get("/search", params={"q": "%%"})
    assert "Atlas shop" not in page.text


async def test_search_only_covers_what_the_account_may_see(
    client: Any, login_as: Any, db_session_factory: Any
) -> None:
    await _seed(db_session_factory)
    await login_as(client, permissions={Permission.MACHINE_VIEW})

    page = await client.get("/search", params={"q": "atlas"})
    assert "atlas-web1" in page.text and "Atlas shop" in page.text
    for hidden in ("Atlas nightly update", "Atlas outages", "/machine-groups/"):
        assert hidden not in page.text


async def test_api_search(client: Any, db_session_factory: Any) -> None:
    await _seed(db_session_factory)
    headers = await _api_token(client)

    found = await client.get("/api/v1/search", params={"q": "atlas"}, headers=headers)
    assert found.status_code == 200
    kinds = {group["kind"]: group["hits"] for group in found.json()["results"]}
    assert set(kinds) == {"machines", "groups", "checks", "scheduled_tasks", "notification_rules"}
    assert kinds["machines"][0]["label"] == "atlas-web1"
    assert kinds["machines"][0]["href"].startswith("/machines/")

    short = await client.get("/api/v1/search", params={"q": "a"}, headers=headers)
    assert short.status_code == 422
