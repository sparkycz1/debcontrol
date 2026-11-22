"""Disks followed by serial number (`app.services.disk_history`): reading
wear, writes and error counters, ZFS members, events, the prediction, the
health findings, the pages and the REST API."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select

from app.db.models.disk import Disk, DiskEvent, DiskSample
from app.db.models.machine import AuthMethod, Machine
from app.db.models.notification_rule import NotificationEventType
from app.services import disk_history, health_events, machine_health
from app.ssh.proxmox import parse_zfs_pools
from app.ssh.smart import IO_ERRORS_PREFIX, SMART_DEVICE_DELIMITER, parse_smart_section
from tests.test_api_v1_extended import _api_token

TH = disk_history.DEFAULT_THRESHOLDS

_NVME = {
    "device": {"protocol": "NVMe"},
    "model_name": "Samsung SSD 980",
    "serial_number": "S64DNX0R123456",
    "smart_status": {"passed": True},
    "nvme_smart_health_information_log": {
        "percentage_used": 12,
        "data_units_written": 1000,
        "data_units_read": 2000,
        "media_errors": 0,
        "num_err_log_entries": 3,
        "unsafe_shutdowns": 7,
    },
    "temperature": {"current": 45},
}

_ATA = {
    "device": {"protocol": "ATA"},
    "model_name": "WDC WD40EFRX",
    "serial_number": "WD-WCC7K1234567",
    "rotation_rate": 5400,
    "logical_block_size": 512,
    "smart_status": {"passed": True},
    "ata_smart_attributes": {
        "table": [
            {"id": 5, "name": "Reallocated_Sector_Ct", "value": 200, "raw": {"value": 2}},
            {"id": 197, "name": "Current_Pending_Sector", "value": 200, "raw": {"value": 0}},
            {"id": 199, "name": "UDMA_CRC_Error_Count", "value": 200, "raw": {"value": 1}},
            {"id": 241, "name": "Total_LBAs_Written", "value": 100, "raw": {"value": 4096}},
        ]
    },
    "temperature": {"current": 38},
    "power_on_time": {"hours": 1000},
}


def _section(*devices: tuple[str, dict[str, Any], str]) -> str:
    out = []
    for name, doc, io in devices:
        out += [f"{SMART_DEVICE_DELIMITER} {name}", f"{IO_ERRORS_PREFIX} {io}", json.dumps(doc)]
    return "\n".join(out)


def test_smart_section_reads_wear_writes_and_counters() -> None:
    devices = parse_smart_section(_section(("nvme0n1", _NVME, ""), ("sda", _ATA, "0x1a")))
    assert devices is not None
    nvme, ata = devices
    assert nvme["wear_percent"] == 12.0
    assert nvme["written_bytes"] == 512_000_000
    assert nvme["read_bytes"] == 1_024_000_000
    assert nvme["counters"] == {"media_errors": 0, "error_log_entries": 3, "unsafe_shutdowns": 7}
    assert ata["wear_percent"] is None
    assert ata["written_bytes"] == 4096 * 512
    assert ata["counters"] == {"reallocated": 2, "pending": 0, "crc_errors": 1, "io_errors": 26}


def test_zfs_status_lists_members_with_errors() -> None:
    status = (
        "  pool: tank\n state: DEGRADED\nconfig:\n\n"
        "\tNAME                                STATE     READ WRITE CKSUM\n"
        "\ttank                                DEGRADED     0     0     0\n"
        "\t  mirror-0                          DEGRADED     0     0     0\n"
        "\t    ata-WDC_WD40EFRX_WD-WCC7K1234567  FAULTED      3     1  1.2K\n"
        "\t    sdb1                            ONLINE       0     0     0\n"
        "\nerrors: No known data errors\n"
    )
    pools = parse_zfs_pools("tank\t100\t50\t50\t1\t50\tDEGRADED", status)
    assert pools is not None
    devices = pools[0]["devices"]
    assert [d["name"] for d in devices] == ["ata-WDC_WD40EFRX_WD-WCC7K1234567", "sdb1"]
    assert devices[0]["cksum"] == 1200 and devices[0]["state"] == "FAULTED"
    member = disk_history.zfs_membership({"serial": "WD-WCC7K1234567"}, pools)
    assert member is not None and member["pool"] == "tank" and member["read"] == 3
    assert disk_history.zfs_membership({"serial": "", "device": "/dev/sdb"}, pools) is not None
    assert disk_history.zfs_membership({"serial": "", "device": "/dev/sdc"}, pools) is None


def test_temperature_and_wear_levels_by_kind() -> None:
    assert disk_history.temperature_class({"type": "nvme"}) == "nvme"
    assert disk_history.temperature_class({"type": "sata", "rotation_rpm": 7200}) == "hdd"
    assert disk_history.temperature_class({"type": "sata"}) == "ssd"
    assert disk_history.temperature_level({"rotation_rpm": 5400, "temperature_c": 55}, TH) == (
        "warning"
    )
    assert disk_history.temperature_level({"type": "nvme", "temperature_c": 55}, TH) is None
    assert disk_history.wear_level({"wear_percent": 96}, TH) == "critical"


def test_predict() -> None:
    now = datetime(2026, 11, 22, tzinfo=UTC)
    assert disk_history.predict([], {"passed": True}, now)["risk"] == "low"
    assert disk_history.predict([], {"passed": False}, now)["risk"] == "failing"
    grow = [
        (now - timedelta(days=10), None, {"reallocated": 0}),
        (now - timedelta(days=5), None, {"reallocated": 4}),
    ]
    assert disk_history.predict(grow, {}, now)["risk"] == "elevated"
    grow.append((now - timedelta(days=1), None, {"reallocated": 9}))
    assert disk_history.predict(grow, {}, now)["risk"] == "high"
    crc = [(now - timedelta(days=3), None, {"crc_errors": 1}), (now, None, {"crc_errors": 2})]
    assert disk_history.predict(crc, {}, now)["risk"] == "elevated"
    # Wear 10 % a month → 100 % in about 6 months.
    wear: list[tuple[datetime, float | None, dict[str, int] | None]] = [
        (now - timedelta(days=60 - d), 50.0 + d / 3, {}) for d in range(0, 61, 10)
    ]
    result = disk_history.predict(wear, {"wear_percent": 70.0}, now)
    assert result["risk"] == "elevated" and 60 <= result["wear_days_left"] <= 120


def _machine(name: str = "pve1", **kwargs: Any) -> Machine:
    return Machine(
        name=name,
        ip_address="10.0.0.5",
        port=22,
        username="root",
        auth_method=AuthMethod.PASSWORD,
        host_key_fingerprint="SHA256:abc",
        **kwargs,
    )


def _ata(**changes: Any) -> dict[str, Any]:
    device = {
        "device": "/dev/sda",
        "model": "WDC WD40EFRX",
        "serial": "WD-WCC7K1234567",
        "type": "sata",
        "rotation_rpm": 5400,
        "passed": True,
        "temperature_c": 38,
        "wear_percent": None,
        "counters": {"reallocated": 0, "crc_errors": 0},
        "attributes": [],
    }
    device.update(changes)
    return device


async def test_record_follows_a_disk_and_its_events(db_session_factory: Any) -> None:
    now = datetime(2026, 11, 22, 10, tzinfo=UTC)
    async with db_session_factory() as db:
        one, two = _machine("pve1"), _machine("pve2")
        db.add_all([one, two])
        await db.flush()

        one.smart_devices = [_ata()]
        events = await disk_history.record(db, one, TH, now)
        assert [e.kind for e in events] == ["first_seen"]
        assert one.smart_devices[0]["disk_id"]
        await db.commit()

        # Ten minutes later, nothing changed: no new sample, no event.
        one.smart_devices = [_ata()]
        assert await disk_history.record(db, one, TH, now + timedelta(minutes=10)) == []
        await db.commit()
        assert len((await db.execute(select(DiskSample))).scalars().all()) == 1

        # Sectors reallocated, too hot: events and a sample at once.
        one.smart_devices = [_ata(counters={"reallocated": 8, "crc_errors": 0}, temperature_c=61)]
        events = await disk_history.record(db, one, TH, now + timedelta(minutes=20))
        assert sorted(e.kind for e in events) == ["counter", "temperature"]
        await db.commit()
        assert len((await db.execute(select(DiskSample))).scalars().all()) == 2

        # Pulled from pve1 ...
        one.smart_devices = [_ata(device="/dev/sdb", serial="OTHER", model="Other")]
        events = await disk_history.record(db, one, TH, now + timedelta(minutes=30))
        assert sorted(e.kind for e in events) == ["first_seen", "missing"]
        await db.commit()

        # ... and put into pve2: the same disk, with its history.
        two.smart_devices = [_ata(counters={"reallocated": 8, "crc_errors": 0})]
        events = await disk_history.record(db, two, TH, now + timedelta(hours=2))
        assert [e.kind for e in events] == ["moved"]
        await db.commit()

        disk = (
            await db.execute(select(Disk).where(Disk.serial == "WD-WCC7K1234567"))
        ).scalar_one()
        assert disk.machine_id == two.id and disk.machine_name == "pve2"
        assert disk.event_count == 5
        assert disk.prediction is not None and disk.prediction["risk"] == "elevated"
        texts = [
            disk_history.event_text(e)
            for e in (await db.execute(select(DiskEvent).where(DiskEvent.disk_id == disk.id)))
            .scalars()
            .all()
        ]
        assert "Reallocated sectors: 0 → 8" in texts
        assert "Moved from pve1 to pve2" in texts


async def test_health_findings_and_notification(
    db_session_factory: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    machine = _machine(
        smart_devices=[
            _ata(temperature_c=65, prediction={"risk": "high"}),
            {**_ata(device="/dev/nvme0n1", type="nvme", rotation_rpm=None,
                    serial="N1", wear_percent=85, temperature_c=50)},
        ]
    )
    findings = {f.key: f.severity for f in machine_health.evaluate(
        machine, [], machine_health.Thresholds()
    )}
    assert findings["disks.temperature:/dev/sda"] == "critical"
    assert findings["disks.risk:/dev/sda"] == "critical"
    assert findings["disks.wear:/dev/nvme0n1"] == "warning"
    assert "disks.temperature:/dev/nvme0n1" not in findings

    sent: list[tuple[NotificationEventType, dict[str, Any]]] = []

    async def _fake_notify(db: Any, event: Any, *, machine: Any = None, context: Any = None,
                           **_kw: Any) -> None:
        sent.append((event, context))

    monkeypatch.setattr(health_events, "notify", _fake_notify)
    now = datetime(2026, 11, 22, 10, tzinfo=UTC)
    async with db_session_factory() as db:
        m = _machine()
        db.add(m)
        await db.flush()
        m.smart_devices = [_ata()]
        await disk_history.record(db, m, TH, now)
        m.smart_devices = [_ata(counters={"reallocated": 3, "crc_errors": 0})]
        events = await disk_history.record(db, m, TH, now + timedelta(hours=1))
        await db.commit()
        await health_events.notify_disk_events(db, m, events)
    assert len(sent) == 1
    event, context = sent[0]
    assert event is NotificationEventType.DISK_WARNING
    assert "Reallocated sectors: 0 → 3" in context["details"]


async def _seed_disk(db_session_factory: Any) -> str:
    now = datetime.now(UTC)
    async with db_session_factory() as db:
        m = _machine()
        db.add(m)
        await db.flush()
        m.smart_devices = [_ata(attributes=[{"id": 5, "name": "Reallocated_Sector_Ct",
                                             "value": 200, "worst": 200, "threshold": 140,
                                             "raw": "0", "failing": False}])]
        await disk_history.record(db, m, TH, now - timedelta(hours=2))
        m.smart_devices = [_ata(counters={"reallocated": 1, "crc_errors": 0}, temperature_c=41)]
        await disk_history.record(db, m, TH, now)
        await db.commit()
        disk = (await db.execute(select(Disk))).scalar_one()
        return str(disk.id)


async def test_disk_pages_render(client: Any, db_session_factory: Any) -> None:
    disk_id = await _seed_disk(db_session_factory)
    listing = await client.get("/disks")
    assert listing.status_code == 200 and "WD-WCC7K1234567" in listing.text
    assert f"/disks/{disk_id}" in listing.text
    detail = await client.get(f"/disks/{disk_id}?days=7")
    assert detail.status_code == 200
    assert "Reallocated sectors: 0 → 1" in detail.text
    assert "style=" not in detail.text and "<style" not in detail.text
    report = await client.get(f"/disks/{disk_id}/report")
    assert report.status_code == 200 and "data-print" in report.text
    assert (await client.get("/disks?risk=failing")).status_code == 200
    missing = "00000000-0000-0000-0000-000000000000"
    assert (await client.get(f"/disks/{missing}")).status_code == 404


async def test_disks_api(client: Any, db_session_factory: Any) -> None:
    disk_id = await _seed_disk(db_session_factory)
    headers = await _api_token(client)
    disks = (await client.get("/api/v1/disks", headers=headers)).json()
    assert [d["serial"] for d in disks] == ["WD-WCC7K1234567"]
    one = (await client.get(f"/api/v1/disks/{disk_id}", headers=headers)).json()
    assert one["counters"]["reallocated"] == 1 and one["attributes"] == []
    samples = (await client.get(f"/api/v1/disks/{disk_id}/samples?days=1",
                                headers=headers)).json()
    assert [s["temperature_c"] for s in samples] == [38.0, 41.0]
    events = (await client.get(f"/api/v1/disks/{disk_id}/events", headers=headers)).json()
    assert {e["kind"] for e in events} == {"first_seen", "counter"}
    assert (await client.get("/api/v1/disks?risk=nope", headers=headers)).status_code == 422
