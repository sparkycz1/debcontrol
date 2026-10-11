"""Update batches: the page of recent batches, a batch's own page with its
counts, and the way back to the batch from one machine's update run
(`app.services.update_batches`). Web and REST API."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from httpx2 import AsyncClient

from app.db.models.machine import AuthMethod, Machine
from app.db.models.machine_update_run import MachineUpdateRun, UpdateRunStatus, UpgradeStrategy
from tests.test_update_history import _api_token


async def _create_machine(db_session_factory: Any, name: str) -> uuid.UUID:
    async with db_session_factory() as db:
        machine = Machine(
            name=name,
            ip_address=f"10.20.{uuid.uuid4().int % 250}.{uuid.uuid4().int % 250 + 1}",
            port=22,
            username="admin",
            auth_method=AuthMethod.SSH_KEY,
        )
        db.add(machine)
        await db.commit()
        return machine.id


async def _batch(
    client: AsyncClient,
    db_session_factory: Any,
    statuses: dict[str, UpdateRunStatus],
    *,
    minutes_ago: int = 5,
) -> tuple[uuid.UUID, dict[str, tuple[uuid.UUID, uuid.UUID]]]:
    """One batch with a run per named machine. Returns the batch id and
    {machine name: (machine id, run id)}."""
    batch_id = uuid.uuid4()
    runs: dict[str, tuple[uuid.UUID, uuid.UUID]] = {}
    created = datetime.now(UTC) - timedelta(minutes=minutes_ago)
    for name, status in statuses.items():
        machine_id = await _create_machine(db_session_factory, name)
        async with db_session_factory() as db:
            run = MachineUpdateRun(
                machine_id=machine_id,
                strategy=UpgradeStrategy.FULL_UPGRADE,
                status=status,
                batch_id=batch_id,
                created_at=created,
                error="apt exited with status 100." if status == UpdateRunStatus.FAILED else None,
            )
            db.add(run)
            await db.commit()
            runs[name] = (machine_id, run.id)
    return batch_id, runs


async def test_run_page_leads_back_to_its_batch(
    client: AsyncClient, db_session_factory: Any
) -> None:
    batch_id, runs = await _batch(
        client,
        db_session_factory,
        {
            "web-b": UpdateRunStatus.RUNNING,
            "web-a": UpdateRunStatus.SUCCEEDED,
            "web-c": UpdateRunStatus.FAILED,
        },
    )
    machine_id, run_id = runs["web-b"]

    page = await client.get(f"/machines/{machine_id}/updates/{run_id}")

    assert page.status_code == 200
    assert f'href="/machine-groups/batches/{batch_id}"' in page.text
    assert "Back to the batch (3 machines)" in page.text
    # Every machine of the batch is one click away, in name order.
    strip = page.text[page.text.index("batch-strip") :]
    positions = [strip.index(f"/machines/{runs[name][0]}/updates/") for name in runs]
    assert positions[1] < positions[0] < positions[2]
    assert 'aria-current="page"' in page.text


async def test_a_run_outside_a_batch_has_no_batch_links(
    client: AsyncClient, db_session_factory: Any
) -> None:
    machine_id = await _create_machine(db_session_factory, "solo")
    async with db_session_factory() as db:
        run = MachineUpdateRun(
            machine_id=machine_id,
            strategy=UpgradeStrategy.FULL_UPGRADE,
            status=UpdateRunStatus.SUCCEEDED,
            batch_id=uuid.uuid4(),  # a batch of one: nothing to go back to
        )
        db.add(run)
        await db.commit()
        run_id = run.id

    page = await client.get(f"/machines/{machine_id}/updates/{run_id}")

    assert page.status_code == 200
    assert "Back to the batch" not in page.text
    assert "batch-strip" not in page.text


async def test_batch_page_counts_and_recent_batches(
    client: AsyncClient, db_session_factory: Any
) -> None:
    older, _ = await _batch(
        client,
        db_session_factory,
        {"old-1": UpdateRunStatus.SUCCEEDED, "old-2": UpdateRunStatus.SUCCEEDED},
        minutes_ago=600,
    )
    newer, runs = await _batch(
        client,
        db_session_factory,
        {
            "new-1": UpdateRunStatus.SUCCEEDED,
            "new-2": UpdateRunStatus.PENDING,
            "new-3": UpdateRunStatus.FAILED,
        },
    )

    batch_page = await client.get(f"/machine-groups/batches/{newer}")
    listing = await client.get("/machine-groups/batches")
    history = await client.get(f"/machines/{runs['new-1'][0]}/updates")
    machines = await client.get("/machines")

    assert batch_page.status_code == 200
    for text in ("1 done", "1 waiting", "1 failed", "of 3", "apt exited with status 100."):
        assert text in batch_page.text, text
    # Still unfinished: the table keeps refreshing itself.
    assert f'hx-get="/machine-groups/batches/{newer}/status"' in batch_page.text
    assert 'href="/machine-groups/batches"' in batch_page.text

    assert listing.status_code == 200
    assert listing.text.index(str(newer)) < listing.text.index(str(older))
    assert "2 done" in listing.text and "of 2" in listing.text
    assert f"/machine-groups/batches/{newer}" in history.text
    assert 'href="/machine-groups/batches"' in machines.text


async def test_finished_batch_stops_refreshing(
    client: AsyncClient, db_session_factory: Any
) -> None:
    batch_id, _ = await _batch(
        client,
        db_session_factory,
        {"done-1": UpdateRunStatus.SUCCEEDED, "done-2": UpdateRunStatus.FAILED},
    )

    status = await client.get(f"/machine-groups/batches/{batch_id}/status")

    assert status.status_code == 200
    assert "hx-get" not in status.text


async def test_api_lists_batches_with_counts(
    client: AsyncClient, db_session_factory: Any
) -> None:
    batch_id, _ = await _batch(
        client,
        db_session_factory,
        {"api-1": UpdateRunStatus.SUCCEEDED, "api-2": UpdateRunStatus.RUNNING},
    )
    headers = await _api_token(client)

    listing = await client.get("/api/v1/machine-groups/batches", headers=headers)
    detail = await client.get(f"/api/v1/machine-groups/batches/{batch_id}", headers=headers)
    missing = await client.get(f"/api/v1/machine-groups/batches/{uuid.uuid4()}", headers=headers)

    assert listing.status_code == 200
    (batch,) = listing.json()["batches"]
    assert batch["batch_id"] == str(batch_id)
    assert batch["strategy"] == "full_upgrade"
    assert (batch["total"], batch["succeeded"], batch["running"]) == (2, 1, 1)
    assert detail.json()["total"] == 2 and len(detail.json()["runs"]) == 2
    assert missing.status_code == 404
