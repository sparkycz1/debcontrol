"""Full update-run history per machine — `GET /machines/{id}/updates` (web)
and `GET /api/v1/machines/{id}/update-runs` (API), both paginated/filterable
by status. See `app/web/routes/machines.py` and `app/web/routes/api_v1.py`.
"""

from __future__ import annotations

import re

from httpx import AsyncClient

from app.db.models.machine_update_run import MachineUpdateRun, UpdateRunStatus, UpgradeStrategy
from tests.test_web import _create_machine, _pin_host_key


async def _api_token(client: AsyncClient) -> dict[str, str]:
    await client.get("/account")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/account/api-tokens", data={"name": "api-test", "csrf_token": csrf_token}
    )
    match = re.search(r"<textarea readonly rows=\"2\">([^<]+)</textarea>", response.text)
    assert match is not None
    return {"Authorization": f"Bearer {match.group(1)}"}


async def _create_runs(db_session_factory, machine_id, count: int, status: UpdateRunStatus) -> None:
    async with db_session_factory() as db:
        for _ in range(count):
            db.add(
                MachineUpdateRun(
                    machine_id=machine_id,
                    strategy=UpgradeStrategy.DIST_UPGRADE,
                    status=status,
                )
            )
        await db.commit()


async def test_update_history_page_lists_every_run(client, db_session_factory):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, name="hist1", ip_address="10.9.0.1")
    await _pin_host_key(db_session_factory, machine_id)

    await _create_runs(db_session_factory, machine_id, 7, UpdateRunStatus.SUCCEEDED)

    response = await client.get(f"/machines/{machine_id}/updates")
    assert response.status_code == 200
    assert response.text.count("succeeded") >= 7


async def test_update_history_filters_by_status(client, db_session_factory):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, name="hist2", ip_address="10.9.0.2")
    await _pin_host_key(db_session_factory, machine_id)

    await _create_runs(db_session_factory, machine_id, 2, UpdateRunStatus.SUCCEEDED)
    await _create_runs(db_session_factory, machine_id, 3, UpdateRunStatus.FAILED)

    response = await client.get(f"/machines/{machine_id}/updates?status_filter=failed")
    assert response.status_code == 200
    assert response.text.count("failed") >= 3
    assert ">succeeded</span>" not in response.text


async def test_update_history_paginates(client, db_session_factory):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, name="hist3", ip_address="10.9.0.3")
    await _pin_host_key(db_session_factory, machine_id)

    await _create_runs(db_session_factory, machine_id, 60, UpdateRunStatus.SUCCEEDED)

    page1 = await client.get(f"/machines/{machine_id}/updates")
    assert page1.status_code == 200
    assert "Older" in page1.text

    page2 = await client.get(f"/machines/{machine_id}/updates?page=2")
    assert page2.status_code == 200
    assert "Newer" in page2.text


async def test_update_history_link_from_detail_page(client, db_session_factory):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, name="hist4", ip_address="10.9.0.4")
    await _pin_host_key(db_session_factory, machine_id)
    await _create_runs(db_session_factory, machine_id, 1, UpdateRunStatus.SUCCEEDED)

    detail = await client.get(f"/machines/{machine_id}")
    assert f"/machines/{machine_id}/updates" in detail.text


async def test_api_update_runs_endpoint(client, db_session_factory):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, name="hist5", ip_address="10.9.0.5")
    await _pin_host_key(db_session_factory, machine_id)
    await _create_runs(db_session_factory, machine_id, 4, UpdateRunStatus.SUCCEEDED)
    headers = await _api_token(client)

    response = await client.get(
        f"/api/v1/machines/{machine_id}/update-runs", headers=headers
    )
    assert response.status_code == 200
    data = response.json()
    assert len(data["runs"]) == 4
    assert data["has_older"] is False

    filtered = await client.get(
        f"/api/v1/machines/{machine_id}/update-runs?status_filter=failed", headers=headers
    )
    assert filtered.status_code == 200
    assert filtered.json()["runs"] == []
