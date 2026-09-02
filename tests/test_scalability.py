"""Fleet-size scalability guards: pages that fan out per-machine work or
render one row per machine must stay bounded (paginated, aggregate-queried)
rather than silently degrading into "load everything" as the fleet grows
into the hundreds/thousands. See wiki/Host-Requirements.md for the
capacity planning this and the reachability-sweep/DB-pool tuning back.
"""

from __future__ import annotations

import uuid

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db.models.machine import AuthMethod, Machine
from app.db.models.machine_group import MachineGroup


async def _bulk_create_machines(
    db_session_factory: async_sessionmaker[AsyncSession],
    count: int,
    *,
    group_id: uuid.UUID | None = None,
) -> None:
    async with db_session_factory() as session:
        session.add_all(
            Machine(
                name=f"bulk-{i:04d}",
                ip_address=f"10.{(i // 250) % 250}.{i % 250}.1",
                port=22,
                username="admin",
                auth_method=AuthMethod.PASSWORD,
                group_id=group_id,
            )
            for i in range(count)
        )
        await session.commit()


async def test_machines_list_paginates_instead_of_loading_everything(
    client, db_session_factory
):
    await _bulk_create_machines(db_session_factory, 150)

    page_one = await client.get("/machines")
    assert page_one.status_code == 200
    assert page_one.text.count("/machines/") >= 100
    assert 'href="/machines?q=&page=2"' in page_one.text
    assert "Previous" not in page_one.text

    page_two = await client.get("/machines?page=2")
    assert page_two.status_code == 200
    assert "Previous" in page_two.text
    # 150 machines, 100 per page -> exactly 50 left, no third page.
    assert "Next" not in page_two.text


async def test_all_machines_group_paginates_too(client, db_session_factory):
    """`/machine-groups/all` is a second "every machine" view under its own
    URL (see all_machines_group's docstring) — it needs the exact same
    pagination as `/machines`, not just the main list."""
    await _bulk_create_machines(db_session_factory, 150)

    page_one = await client.get("/machine-groups/all")
    assert page_one.status_code == 200
    assert page_one.text.count("/machines/") >= 100
    assert 'href="/machine-groups/all?q=&page=2"' in page_one.text

    page_two = await client.get("/machine-groups/all?page=2")
    assert page_two.status_code == 200
    assert "Previous" in page_two.text
    assert "Next" not in page_two.text


async def test_group_list_shows_member_count_for_many_machines_without_selectinload(
    client, db_session_factory
):
    group_id = uuid.uuid4()
    async with db_session_factory() as session:
        session.add(MachineGroup(id=group_id, name="bulkgroup", description=""))
        await session.commit()
    await _bulk_create_machines(db_session_factory, 120, group_id=group_id)

    response = await client.get("/machine-groups")
    assert response.status_code == 200
    # The count column must reflect all 120 members even though the route no
    # longer loads any of the actual Machine rows to compute it.
    assert ">120<" in response.text
