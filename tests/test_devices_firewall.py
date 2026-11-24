"""Hardware devices (PCIe, USB, IPMI — `app.ssh.peripherals`), UPS through
NUT (`app.ssh.ups`), the packet filter and Fail2Ban (`app.ssh.firewall`):
parsing, storing, the UPS notifications and health findings, the pages
and the REST API."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from httpx2 import AsyncClient

from app.db.models.machine import AuthMethod, Machine
from app.db.models.notification_rule import NotificationEventType
from app.services import health_events, machine_health
from app.ssh import facts, firewall, monitoring, peripherals, ups
from app.ssh.onboarding import SUDO_COMMAND_LIST, build_onboarding_command
from tests.test_update_history import _api_token

LSPCI = """@@LSPCI
Slot:\t0000:00:02.0
Class:\tVGA compatible controller [0300]
Vendor:\tIntel Corporation [8086]
Device:\tCoffeeLake-S GT2 [UHD Graphics 630] [3e92]
Rev:\t02
Driver:\ti915
Module:\ti915

Slot:\t0000:01:00.0
Class:\tEthernet controller [0200]
Vendor:\tIntel Corporation [8086]
Device:\tI210 Gigabit Network Connection [1533]
Driver:\tvfio-pci
IOMMUGroup:\t14
@@IOMMU
0000:00:02.0 1
0000:01:00.0 14
"""

USB = (
    "usb1\t1\t1\t1d6b\t0002\t480\t09\tLinux 6.1 xhci-hcd\txHCI Host Controller\thub,\n"
    "1-3\t1\t2\t051d\t0002\t12\t00\tAmerican Power Conversion\tBack-UPS ES 700\tusbhid,\n"
    "1-4\t1\t3\t0bda\t8153\t5000\t00\tRealtek\tUSB 10/100/1000 LAN\tr8152,\n"
)

IPMI = """@@SDR
CPU Temp         | 45 degrees C      | ok
FAN1             | 1200 RPM          | ok
PSU2 Status      | 0x01              | cr
12V              | 11.20 Volts       | lnc
Chassis Intru    | Not Readable      | ns
@@SEL
   1 | 11/20/2026 | 10:00:00 | Power Supply #0x51 | Power Supply AC lost | Asserted
   2 | 11/23/2026 | 09:15:02 | Temperature #0x30 | Upper Critical going high | Asserted
"""

NFT = json.dumps(
    {
        "nftables": [
            {"metainfo": {"version": "1.0.6"}},
            {"table": {"family": "inet", "name": "filter", "handle": 1}},
            {"chain": {"family": "inet", "table": "filter", "name": "input", "handle": 1,
                       "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}},
            {"chain": {"family": "inet", "table": "filter", "name": "forward", "handle": 2,
                       "type": "filter", "hook": "forward", "prio": 0, "policy": "accept"}},
            {"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": 3,
                      "expr": []}},
            {"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": 4,
                      "expr": []}},
        ]
    }
)

UFW_STATUS = """Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
443                        ALLOW IN    192.168.1.0/24
"""

FAIL2BAN = """@@UNIT active
@@OK
@@JAIL sshd
Status for the jail: sshd
|- Filter
|  |- Currently failed:\t2
|  |- Total failed:\t40
|  `- File list:\t/var/log/auth.log
`- Actions
   |- Currently banned:\t2
   |- Total banned:\t9
   `- Banned IP list:\t192.0.2.7 198.51.100.4
@@BANS
192.0.2.7 \t2026-11-23 08:00:00 + 600 = 2026-11-23 08:10:00
198.51.100.4 \t2026-11-23 09:30:00 + -1 = 9999-12-31 23:59:59
not an ip at all
"""


def _ups_section(status: str, charge: str = "100") -> str:
    return (
        "@@UPS apc\n"
        "battery.charge: " + charge + "\n"
        "battery.runtime: 1500\n"
        "device.mfr: American Power Conversion\n"
        "device.model: Back-UPS ES 700\n"
        "ups.load: 12\n"
        "input.voltage: 231.0\n"
        f"ups.status: {status}\n"
    )


# --- Parsing ----------------------------------------------------------------


def test_lspci_with_driver_and_iommu_groups() -> None:
    devices = peripherals.parse_pci_section(LSPCI)
    assert devices is not None and len(devices) == 2
    gpu, nic = devices
    assert gpu["class"] == "VGA compatible controller" and gpu["class_id"] == "0300"
    assert gpu["vendor"] == "Intel Corporation" and gpu["vendor_id"] == "8086"
    assert gpu["device"] == "CoffeeLake-S GT2 [UHD Graphics 630]" and gpu["device_id"] == "3e92"
    assert gpu["driver"] == "i915"
    # From /sys/kernel/iommu_groups when lspci does not print it.
    assert gpu["iommu_group"] == 1
    assert nic["driver"] == "vfio-pci" and nic["iommu_group"] == 14


def test_pci_from_sysfs_without_pciutils() -> None:
    devices = peripherals.parse_pci_section(
        "@@SYSFS\n0000:00:1f.6\t0x020000\t0x8086\t0x15bb\te1000e\n@@IOMMU\n"
    )
    assert devices == [
        {
            "slot": "0000:00:1f.6",
            "class": "Network controller",
            "class_id": "0200",
            "vendor": None,
            "vendor_id": "8086",
            "device": None,
            "device_id": "15bb",
            "driver": "e1000e",
            "iommu_group": None,
        }
    ]
    assert peripherals.parse_pci_section("") is None


def test_usb_leaves_out_root_hubs() -> None:
    devices = peripherals.parse_usb_section(USB)
    assert devices is not None
    assert [d["product"] for d in devices] == ["Back-UPS ES 700", "USB 10/100/1000 LAN"]
    assert devices[0]["vendor_id"] == "051d" and devices[0]["drivers"] == ["usbhid"]
    assert devices[1]["speed_mbps"] == 5000.0
    assert peripherals.parse_usb_section(USB.splitlines()[0]) is None


def test_ipmi_sensors_events_and_problems() -> None:
    ipmi = peripherals.parse_ipmi_section(IPMI)
    assert ipmi is not None and ipmi["readable"] is True
    by_name = {s["name"]: s for s in ipmi["sensors"]}
    assert "Chassis Intru" not in by_name  # "ns": no such sensor
    assert by_name["CPU Temp"]["value"] == 45.0 and by_name["CPU Temp"]["unit"] == "°C"
    assert by_name["12V"]["status"] == "warning"
    assert by_name["PSU2 Status"]["value"] is None and by_name["PSU2 Status"]["reading"] == "0x01"
    assert ipmi["events"][0]["event"] == "Upper Critical going high"  # newest first
    problems = peripherals.ipmi_problems(ipmi)
    assert [p["name"] for p in problems] == ["PSU2 Status", "12V"]
    assert peripherals.parse_ipmi_section("") is None
    assert peripherals.parse_ipmi_section("@@SDR\n@@SEL\n") == {
        "sensors": [], "events": [], "readable": False
    }


def test_ups_parse_and_power_changes() -> None:
    online = ups.parse_section(_ups_section("OL"))
    assert online is not None
    (device,) = online
    assert device["name"] == "apc" and device["on_battery"] is False
    assert device["charge_percent"] == 100.0 and device["runtime_seconds"] == 1500.0
    assert device["manufacturer"] == "American Power Conversion"
    on_battery = ups.parse_section(_ups_section("OB DISCHRG LB", charge="18"))
    assert on_battery is not None
    assert on_battery[0]["on_battery"] and on_battery[0]["low_battery"]

    went, back = ups.power_changes(online, on_battery)
    assert [u["name"] for u in went] == ["apc"] and back == []
    went, back = ups.power_changes(on_battery, online)
    assert went == [] and [u["name"] for u in back] == ["apc"]
    # Unknown before (first sample after an upgrade): nothing.
    assert ups.power_changes(None, on_battery) == ([], [])
    assert "battery 18 %" in ups.describe(on_battery[0])
    assert ups.parse_section("") is None


def test_firewall_nftables_ufw_and_pve() -> None:
    section = (
        "@@UNIT nftables inactive\n@@UNIT ufw active\n@@UNIT firewalld inactive\n"
        f"@@NFT\n{NFT}\n@@UFWCONF\nENABLED=yes\n@@UFW\n{UFW_STATUS}\n"
        '@@PVECLUSTER\n{"enable": 1, "policy_in": "DROP"}\n@@PVENODE\n{}\n'
    )
    parsed = firewall.parse_firewall_section(section)
    assert parsed is not None
    nft = parsed["nftables"]
    assert nft["rules"] == 2
    assert nft["input_chains"] == [
        {"family": "inet", "table": "filter", "chain": "input", "policy": "drop", "rules": 2}
    ]
    assert parsed["ufw"]["active"] is True and len(parsed["ufw"]["rules"]) == 2
    assert parsed["ufw"]["rules"][1] == {"to": "443", "action": "ALLOW IN",
                                         "from": "192.168.1.0/24"}
    assert parsed["pve"]["cluster_enabled"] is True and parsed["pve"]["node_enabled"] is True
    assert firewall.active_backends(parsed) == ["ufw", "pve-firewall"]
    assert firewall.protection(parsed) == "on"
    assert firewall.input_policy(parsed) == "drop"


def test_firewall_protection_off_and_unknown() -> None:
    accept_only = firewall.parse_firewall_section(
        "@@UNIT nftables active\n@@NFT\n"
        + json.dumps({"nftables": [{"chain": {"family": "inet", "table": "filter",
                                              "name": "input", "hook": "input",
                                              "policy": "accept"}}]})
    )
    assert firewall.protection(accept_only) == "off"
    # nft present but unreadable (no root grant) and nothing else: unknown.
    unreadable = firewall.parse_firewall_section("@@UNIT nftables inactive\n@@NFT\n\n")
    assert unreadable is not None and unreadable["nftables"] is None
    assert firewall.protection(unreadable) == "unknown"
    # Only ufw.conf readable: ENABLED=yes counts.
    conf_only = firewall.parse_firewall_section("@@UFWCONF\nENABLED=yes\n@@UFW\n")
    assert firewall.active_backends(conf_only) == ["ufw"]
    assert firewall.protection(None) == "unknown"
    assert firewall.parse_firewall_section("") is None


def test_fail2ban_jails_and_bans() -> None:
    parsed = firewall.parse_fail2ban_section(FAIL2BAN)
    assert parsed is not None and parsed["status"] == "ok"
    (jail,) = parsed["jails"]
    assert jail["name"] == "sshd"
    assert (jail["currently_failed"], jail["total_failed"]) == (2, 40)
    assert (jail["currently_banned"], jail["total_banned"]) == (2, 9)
    assert [b["ip"] for b in jail["bans"]] == ["198.51.100.4", "192.0.2.7"]
    assert jail["bans"][0]["seconds"] == -1
    totals = firewall.fail2ban_totals(parsed)
    assert totals == {"jails": 1, "currently_banned": 2, "total_banned": 9,
                      "last_ban": "2026-11-23T09:30:00"}
    assert firewall.parse_fail2ban_section("") is None
    assert firewall.parse_fail2ban_section("@@UNIT inactive\n") == {
        "status": "stopped", "jails": []
    }
    assert firewall.parse_fail2ban_section("@@UNIT active\n")["status"] == "no_access"  # type: ignore[index]


def test_jail_names_are_checked() -> None:
    parsed = firewall.parse_fail2ban_section("@@UNIT active\n@@OK\n@@JAIL $(reboot)\n")
    assert parsed == {"status": "ok", "jails": []}


def test_facts_and_monitoring_carry_the_new_sections() -> None:
    raw = (
        f"===PCI===\n{LSPCI}\n===USB===\n{USB}\n===IPMI===\n{IPMI}\n"
        f"===FIREWALL===\n@@UNIT ufw active\n===FAIL2BAN===\n{FAIL2BAN}\n"
    )
    parsed = facts.parse_facts_output(raw)
    assert parsed["pci_devices"] and len(parsed["pci_devices"]) == 2
    assert parsed["usb_devices"] and len(parsed["usb_devices"]) == 2
    assert parsed["ipmi"] and parsed["ipmi"]["readable"]
    assert parsed["firewall"] == {
        "units": {"ufw": "active"}, "nftables_installed": False, "nftables": None,
        "ufw": None, "pve": None,
    }
    assert parsed["fail2ban"] and parsed["fail2ban"]["status"] == "ok"
    for marker in ("===PCI===", "===USB===", "===IPMI===", "===FIREWALL===", "===FAIL2BAN==="):
        assert marker in facts.FACTS_COMMAND
    sample = monitoring.parse_monitoring_output(f"===UPS===\n{_ups_section('OL')}")
    assert sample["ups_devices"] and sample["ups_devices"][0]["name"] == "apc"
    assert "===UPS===" in monitoring.MONITORING_COMMAND


def test_the_sudoers_grant_is_read_only_and_in_the_playbook() -> None:
    for line in (
        "/usr/bin/ipmitool sdr list",
        "/usr/bin/ipmitool sel elist last 20",
        "/usr/sbin/nft -j list ruleset",
        "/usr/sbin/ufw status verbose",
        "/usr/bin/fail2ban-client get * banip --with-time",
    ):
        assert line in SUDO_COMMAND_LIST
    assert "fail2ban-client set" not in SUDO_COMMAND_LIST
    assert SUDO_COMMAND_LIST in build_onboarding_command("ssh-ed25519 AAAA test")
    playbook = Path(__file__).resolve().parent.parent / "ansible" / "debcontrol-onboard.yml"
    assert f"NOPASSWD: {SUDO_COMMAND_LIST}" in playbook.read_text(encoding="utf-8")


# --- Health and notifications -------------------------------------------------


def _machine(**extra: Any) -> Machine:
    return Machine(
        id=uuid.uuid4(), name="nas", ip_address="10.0.0.9", port=22, username="admin",
        auth_method=AuthMethod.SSH_KEY, **extra,
    )


def test_health_reports_ups_and_ipmi_problems() -> None:
    machine = _machine(
        ups_devices=ups.parse_section(_ups_section("OB DISCHRG LB RB", charge="10")),
        ipmi=peripherals.parse_ipmi_section(IPMI),
    )
    findings = machine_health.evaluate(machine, [], machine_health.Thresholds())
    by_key = {f.key: f for f in findings}
    assert by_key["hardware.ups:apc"].severity == "critical"
    assert by_key["hardware.ups:apc"].message == "ups_low_battery"
    assert by_key["hardware.ups_battery:apc"].severity == "warning"
    assert by_key["hardware.ipmi:PSU2 Status"].severity == "critical"
    assert by_key["hardware.ipmi:12V"].params["reading"] == "11.2 V"
    assert all(f.category == "hardware" for f in by_key.values())
    assert "hardware" in machine_health.CATEGORIES
    text = machine_health.finding_text(by_key["hardware.ups:apc"], "cs")
    assert "apc" in text and "{" not in text


async def test_ups_notifications_on_the_transition(monkeypatch: pytest.MonkeyPatch) -> None:
    sent: list[tuple[NotificationEventType, dict[str, Any]]] = []

    async def fake_notify(_db: Any, event: NotificationEventType, **kwargs: Any) -> None:
        sent.append((event, kwargs.get("context") or {}))

    monkeypatch.setattr(health_events, "notify", fake_notify)
    online = ups.parse_section(_ups_section("OL"))
    machine = _machine(ups_devices=ups.parse_section(_ups_section("OB DISCHRG", charge="80")))
    common: dict[str, Any] = {
        "previous_failed_units": None, "previous_smart_disks": None,
        "current_smart_disks": None, "previous_zfs_pools": None,
    }
    await health_events.notify_monitoring_changes(None, machine, previous_ups=online, **common)  # type: ignore[arg-type]
    assert [e for e, _ in sent] == [NotificationEventType.UPS_ON_BATTERY]
    assert sent[0][1]["ups"] == "apc" and "battery 80 %" in sent[0][1]["details"]
    sent.clear()
    # Still on battery: no repeat.
    await health_events.notify_monitoring_changes(
        None, machine, previous_ups=machine.ups_devices, **common  # type: ignore[arg-type]
    )
    assert sent == []
    machine.ups_devices = online
    await health_events.notify_monitoring_changes(
        None, machine, previous_ups=ups.parse_section(_ups_section("OB")), **common  # type: ignore[arg-type]
    )
    assert [e for e, _ in sent] == [NotificationEventType.UPS_POWER_RESTORED]


# --- Pages and API ------------------------------------------------------------


async def _seed(db_session_factory: Any, name: str = "nas", **extra: Any) -> uuid.UUID:
    async with db_session_factory() as db:
        machine = Machine(
            name=name, ip_address=f"10.40.0.{uuid.uuid4().int % 250 + 1}", port=22,
            username="admin", auth_method=AuthMethod.SSH_KEY,
            host_key_fingerprint="SHA256:test", is_physical=True, **extra,
        )
        db.add(machine)
        await db.commit()
        return machine.id


def _full() -> dict[str, Any]:
    return {
        "pci_devices": peripherals.parse_pci_section(LSPCI),
        "usb_devices": peripherals.parse_usb_section(USB),
        "ipmi": peripherals.parse_ipmi_section(IPMI),
        "ups_devices": ups.parse_section(_ups_section("OB DISCHRG", charge="60")),
        "firewall": firewall.parse_firewall_section(
            f"@@UNIT ufw active\n@@NFT\n{NFT}\n@@UFWCONF\nENABLED=yes\n@@UFW\n{UFW_STATUS}\n"
        ),
        "fail2ban": firewall.parse_fail2ban_section(FAIL2BAN),
    }


async def test_monitoring_tab_shows_the_device_cards(
    client: AsyncClient, db_session_factory: Any
) -> None:
    machine_id = await _seed(
        db_session_factory, monitoring_updated_at=datetime.now(UTC), **_full()
    )
    response = await client.get(f"/machines/{machine_id}/monitoring")
    assert response.status_code == 200
    for anchor in ('id="ups"', 'id="ipmi"', 'id="pci"', 'id="usb"'):
        assert anchor in response.text
    assert "Back-UPS ES 700" in response.text
    assert "vfio-pci" in response.text
    assert "Upper Critical going high" in response.text


async def test_security_tab_and_fleet_firewall_page(
    client: AsyncClient, db_session_factory: Any
) -> None:
    protected = await _seed(db_session_factory, **_full())
    bare = await _seed(
        db_session_factory, name="bare",
        firewall=firewall.parse_firewall_section(
            '@@UNIT nftables inactive\n@@NFT\n{"nftables": []}\n'
        ),
    )
    response = await client.get(f"/machines/{protected}/security")
    assert response.status_code == 200
    assert 'id="firewall"' in response.text and "198.51.100.4" in response.text
    assert 'id="fail2ban-jails"' in response.text

    response = await client.get("/security/firewall")
    assert response.status_code == 200
    text = response.text
    assert 'id="firewall-table"' in text and 'id="fleet-bans"' in text
    # Unprotected first.
    assert text.index(f"/machines/{bare}/security") < text.index(f"/machines/{protected}/security")
    assert "/security/firewall" in (await client.get("/security/updates")).text


async def test_api_firewall_and_hardware(client: AsyncClient, db_session_factory: Any) -> None:
    machine_id = await _seed(db_session_factory, **_full())
    headers = await _api_token(client)
    response = await client.get(f"/api/v1/machines/{machine_id}/firewall", headers=headers)
    assert response.status_code == 200
    body = response.json()
    assert body["protection"] == "on" and body["backends"] == ["ufw"]
    assert body["fail2ban"]["jails"][0]["name"] == "sshd"
    assert body["input_policy"] == "drop"

    fleet = (await client.get("/api/v1/security/firewall", headers=headers)).json()
    assert fleet["machines"][0]["machine_id"] == str(machine_id)
    assert fleet["machines"][0]["fail2ban"]["currently_banned"] == 2
    assert fleet["recent_bans"][0]["ip"] == "198.51.100.4"
    assert fleet["recent_bans"][0]["machine_name"] == "nas"

    hardware = (
        await client.get(f"/api/v1/machines/{machine_id}/hardware", headers=headers)
    ).json()
    assert hardware["pci_devices"][1]["iommu_group"] == 14
    assert hardware["usb_devices"][0]["vendor_id"] == "051d"
    assert hardware["ipmi"]["readable"] is True
    assert hardware["ups_devices"][0]["on_battery"] is True
