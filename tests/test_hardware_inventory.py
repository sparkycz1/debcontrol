"""Hardware inventory and warranties (`app.services.hardware_inventory`):
read from the firmware, completed by a person, and not a thing for a
virtual machine."""

from __future__ import annotations

from datetime import date, datetime, timedelta
from typing import Any

from httpx2 import AsyncClient

from app.services import hardware_inventory
from app.services.condition_fields import CONDITION_FIELDS
from app.ssh.facts import parse_facts_output
from app.ssh.hardware import parse_hardware
from tests.test_homelab_round import _add_machine
from tests.test_update_history import _api_token


def test_firmware_placeholders_are_not_facts() -> None:
    real = parse_hardware("vendor=Dell Inc.\nmodel=PowerEdge  R740\nserial=ABC1234\n")
    blank = parse_hardware(
        "vendor=System manufacturer\nmodel=To Be Filled By O.E.M.\nserial=Default string\n"
    )
    facts = parse_facts_output("===HARDWARE===\nvendor=Supermicro\nmodel=\nserial=S123\n")

    assert real == {"vendor": "Dell Inc.", "model": "PowerEdge R740", "serial": "ABC1234"}
    assert blank == {"vendor": None, "model": None, "serial": None}
    assert (facts["hw_vendor"], facts["hw_model"], facts["hw_serial"]) == (
        "Supermicro",
        None,
        "S123",
    )


def test_warranty_only_counts_for_physical_machines() -> None:
    class _M:
        def __init__(self, is_physical: bool | None, until: date | None) -> None:
            self.is_physical = is_physical
            self.warranty_until = until

    today = date(2026, 10, 12)

    assert hardware_inventory.warranty_days_left(_M(True, date(2026, 11, 1)), today) == 20
    assert hardware_inventory.warranty_days_left(_M(None, date(2026, 10, 1)), today) == -11
    assert hardware_inventory.warranty_days_left(_M(False, date(2026, 11, 1)), today) is None
    assert hardware_inventory.warranty_days_left(_M(True, None), today) is None
    field: Any = CONDITION_FIELDS["hardware.warranty_days_left"]
    assert field.accessor(_M(False, date(2026, 11, 1)), None, None) is None


async def test_recording_and_listing(client: AsyncClient, db_session_factory: Any) -> None:
    soon = (datetime.now().date() + timedelta(days=30)).isoformat()
    server = await _add_machine(
        db_session_factory,
        name="rack1",
        ip_address="10.0.6.1",
        is_physical=True,
        hw_vendor="Dell Inc.",
        hw_model="PowerEdge R740",
        hw_serial="ABC1234",
    )
    old = await _add_machine(
        db_session_factory, name="rack2", ip_address="10.0.6.2", is_physical=True
    )
    vm = await _add_machine(
        db_session_factory, name="vm1", ip_address="10.0.6.3", is_physical=False
    )
    await client.get(f"/machines/{server}")
    csrf = client.cookies.get("csrftoken")

    saved = await client.post(
        f"/machines/{server}/asset",
        data={
            "csrf_token": csrf,
            "purchase_date": "2023-05-01",
            "warranty_until": soon,
            "asset_note": "Rack 4, unit 12",
        },
        follow_redirects=False,
    )
    backwards = await client.post(
        f"/machines/{old}/asset",
        data={"csrf_token": csrf, "purchase_date": "2024-01-01", "warranty_until": "2023-01-01"},
        follow_redirects=False,
    )
    on_vm = await client.post(
        f"/machines/{vm}/asset", data={"csrf_token": csrf, "warranty_until": soon}
    )
    headers = await _api_token(client)
    expired = await client.put(
        f"/api/v1/machines/{old}/asset",
        headers=headers,
        json={"warranty_until": "2020-01-01", "serial": "MANUAL-1"},
    )

    overview = await client.get(f"/machines/{server}")
    vm_page = await client.get(f"/machines/{vm}")
    listing = await client.get("/machines/hardware")
    api = (await client.get("/api/v1/hardware-inventory", headers=headers)).json()
    one = (await client.get(f"/api/v1/machines/{vm}", headers=headers)).json()

    assert saved.status_code == 303 and "asset_error" not in saved.headers["location"]
    assert "asset_error=" in backwards.headers["location"]
    assert on_vm.status_code == 400
    assert expired.json()["serial"] == "MANUAL-1" and expired.json()["warranty_days_left"] < 0
    assert "Dell Inc. PowerEdge R740" in overview.text and "30 days left" in overview.text
    assert "Rack 4, unit 12" in overview.text
    # A virtual machine has no hardware panel and is not in the list.
    assert 'id="hardware"' not in vm_page.text
    assert "vm1" not in listing.text
    assert listing.text.index("rack2") < listing.text.index("rack1")
    assert [row["machine_name"] for row in api] == ["rack2", "rack1"]
    assert one["hardware"] is None
