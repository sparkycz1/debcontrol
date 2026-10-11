"""Comparing two machines (`app.services.machine_compare`): differing
facts, packages and services, on the page and in the REST API."""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Any

from httpx2 import AsyncClient

from app.db.models.machine_package import MachinePackage
from app.db.models.machine_service import MachineService
from app.services import machine_compare
from app.ssh.packages import PackageSource
from tests.test_homelab_round import _add_machine, _machine
from tests.test_update_history import _api_token


def test_item_diff_sorts_everything_into_four_groups() -> None:
    diff = machine_compare.diff_items(
        {"bash": "5.2-1", "vim": "9.0", "curl": "8.5"},
        {"bash": "5.2-2", "vim": "9.0", "nginx": "1.24"},
    )

    assert diff.only_a == [("curl", "8.5")]
    assert diff.only_b == [("nginx", "1.24")]
    assert diff.different == [("bash", "5.2-1", "5.2-2")]
    assert (diff.same, diff.differences) == (1, 3)


def test_fact_diff_ignores_what_one_side_does_not_know() -> None:
    a = _machine(
        kernel_version="6.1.0-25", os_version="Debian 12", listening_ports=["0.0.0.0:22", ":80"]
    )
    b = _machine(kernel_version="6.1.0-28", os_version=None, listening_ports=["0.0.0.0:22"])

    rows = {row.name: row for row in machine_compare.diff_facts(a, b)}

    assert rows["kernel_version"].differs
    assert (rows["kernel_version"].a, rows["kernel_version"].b) == ("6.1.0-25", "6.1.0-28")
    # Unknown on one machine is not a difference.
    assert not rows["os_version"].differs
    assert rows["listening_ports"].differs
    assert rows["listening_ports"].only_a == [":80"] and rows["listening_ports"].only_b == []
    assert rows["listening_ports"].common == 1
    # Never refreshed on either side: nothing to say.
    assert not rows["admin_users"].differs


async def _two_machines(db_session_factory: Any) -> tuple[uuid.UUID, uuid.UUID]:
    now = datetime.now(UTC)
    first = await _add_machine(
        db_session_factory,
        name="web-1",
        kernel_version="6.1.0-25",
        packages_updated_at=now,
        services_updated_at=now,
    )
    second = await _add_machine(
        db_session_factory,
        name="web-2",
        ip_address="10.0.0.6",
        kernel_version="6.1.0-28",
        packages_updated_at=now,
        services_updated_at=now,
    )
    async with db_session_factory() as db:
        for machine_id, packages, state in (
            (first, {"bash": "5.2-1", "vim": "9.0", "curl": "8.5"}, "active"),
            (second, {"bash": "5.2-2", "vim": "9.0", "nginx": "1.24"}, "failed"),
        ):
            for name, version in packages.items():
                db.add(
                    MachinePackage(
                        machine_id=machine_id, source=PackageSource.APT, name=name, version=version
                    )
                )
            db.add(
                MachineService(
                    machine_id=machine_id,
                    unit="ssh.service",
                    load_state="loaded",
                    active_state=state,
                    sub_state="running" if state == "active" else "failed",
                    description="OpenSSH",
                )
            )
        await db.commit()
    return first, second


async def test_compare_page_and_the_bulk_button(
    client: AsyncClient, db_session_factory: Any
) -> None:
    first, second = await _two_machines(db_session_factory)
    listing = await client.get("/machines")
    match = re.search(r'name="csrf_token" value="([^"]+)"', listing.text)
    assert match is not None
    csrf = match.group(1)

    one = await client.post(
        "/machines/bulk/compare",
        data={"csrf_token": csrf, "machine_ids": [str(first)]},
        follow_redirects=False,
    )
    two = await client.post(
        "/machines/bulk/compare",
        data={"csrf_token": csrf, "machine_ids": [str(second), str(first)]},
        follow_redirects=False,
    )
    page = await client.get(two.headers["location"])
    same = await client.get(f"/machines/compare?a={first}&b={first}")
    unknown = await client.get(f"/machines/compare?a={first}&b={uuid.uuid4()}")

    assert 'formaction="/machines/bulk/compare"' in listing.text
    assert "bulk_error=" in one.headers["location"]
    assert two.headers["location"] == f"/machines/compare?a={first}&b={second}"
    assert page.status_code == 200
    for text in (
        "6.1.0-25",
        "6.1.0-28",
        "Only on web-1 (1)",
        "Only on web-2 (1)",
        "Different on each (1)",
        "5.2-1",
        "active (running)",
        "failed (failed)",
    ):
        assert text in page.text, text
    assert same.status_code == 404 and unknown.status_code == 404


async def test_compare_api(client: AsyncClient, db_session_factory: Any) -> None:
    first, second = await _two_machines(db_session_factory)
    headers = await _api_token(client)

    response = await client.get(f"/api/v1/machines/compare?a={first}&b={second}", headers=headers)
    missing = await client.get(
        f"/api/v1/machines/compare?a={first}&b={uuid.uuid4()}", headers=headers
    )

    assert response.status_code == 200
    body = response.json()
    assert (body["a"]["name"], body["b"]["name"]) == ("web-1", "web-2")
    assert body["packages"]["known"] is True and body["packages"]["same"] == 1
    assert body["packages"]["only_a"] == [{"name": "curl", "value": "8.5"}]
    assert body["packages"]["different"] == [{"name": "bash", "a": "5.2-1", "b": "5.2-2"}]
    assert body["services"]["different"][0]["name"] == "ssh.service"
    kernel = next(row for row in body["facts"] if row["field"] == "kernel_version")
    assert kernel["differs"] is True
    assert missing.status_code == 404
