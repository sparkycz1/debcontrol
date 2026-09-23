from __future__ import annotations

import json

from app.ssh.facts import parse_facts_output
from app.ssh.smart import SMART_DEVICE_DELIMITER, parse_smart_device, parse_smart_section

_NVME = {
    "device": {"name": "/dev/nvme0n1", "type": "nvme", "protocol": "NVMe"},
    "model_name": "SAMSUNG MZVLB512HBJQ-000L7",
    "serial_number": "S4ENNX0T141660",
    "firmware_version": "5M2QEXF7",
    "nvme_total_capacity": 512110190592,
    "smart_status": {"passed": True},
    "nvme_smart_health_information_log": {
        "critical_warning": 0,
        "temperature": 42,
        "percentage_used": 4,
        "temperature_sensors": [42, 47],
    },
    "temperature": {"current": 42},
    "power_cycle_count": 1178,
    "power_on_time": {"hours": 4203},
}

_ATA = {
    "device": {"name": "/dev/sda", "type": "sat", "protocol": "ATA"},
    "model_name": "WDC WD40EFRX",
    "serial_number": "WD-1",
    "user_capacity": {"blocks": 7814037168, "bytes": 4000787030016},
    "rotation_rate": 5400,
    "smart_status": {"passed": False},
    "ata_smart_attributes": {
        "table": [
            {
                "id": 5, "name": "Reallocated_Sector_Ct", "value": 100, "worst": 100,
                "thresh": 140, "when_failed": "now", "raw": {"value": 12, "string": "12"},
            }
        ]
    },
    "power_on_time": {"hours": 100},
}


def test_parse_nvme_device():
    device = parse_smart_device("nvme0n1", json.dumps(_NVME))

    assert device is not None
    assert device["device"] == "/dev/nvme0n1"
    assert device["type"] == "nvme"
    assert device["passed"] is True
    assert device["capacity_bytes"] == 512110190592
    assert device["power_on_hours"] == 4203
    assert device["power_cycles"] == 1178
    assert device["temperature_c"] == 42
    names = {a["name"]: a["raw"] for a in device["attributes"]}
    assert names["PercentageUsed"] == "4"
    assert names["TemperatureSensors"] == "42, 47"


def test_parse_ata_device_flags_failing_attribute():
    device = parse_smart_device("sda", json.dumps(_ATA))

    assert device is not None
    assert device["type"] == "sata"
    assert device["passed"] is False
    assert device["rotation_rpm"] == 5400
    (attr,) = device["attributes"]
    assert attr["id"] == 5
    assert attr["threshold"] == 140
    assert attr["failing"] is True


def test_unreadable_device_is_dropped():
    assert parse_smart_device("sdb", "") is None
    assert parse_smart_device("sdb", json.dumps({"smartctl": {"exit_status": 2}})) is None


def test_parse_section_splits_devices():
    raw = (
        f"{SMART_DEVICE_DELIMITER} nvme0n1\n{json.dumps(_NVME, indent=2)}\n"
        f"{SMART_DEVICE_DELIMITER} sdb\n\n"
        f"{SMART_DEVICE_DELIMITER} sda\n{json.dumps(_ATA)}\n"
    )

    devices = parse_smart_section(raw)

    assert devices is not None
    assert [d["device"] for d in devices] == ["/dev/nvme0n1", "/dev/sda"]


def test_empty_section_means_not_applicable():
    assert parse_smart_section("") is None


def test_facts_output_carries_smart_devices():
    raw = (
        "===HOSTNAME===\nweb1\n===SMART===\n"
        f"{SMART_DEVICE_DELIMITER} nvme0n1\n{json.dumps(_NVME)}\n"
    )
    # Every marker from HOSTNAME to VIRT must appear, in order, before
    # SMART — facts.py still pairs sections positionally.
    markers = (
        "OS", "OS_ID", "KERNEL", "KERNEL_LATEST", "ARCH", "CPU", "CPU_MODEL", "RAM_KB",
        "RAM_SPEED", "DISKS", "UPTIME", "PROCESSES", "FILESYSTEMS", "NETWORK", "VIRT",
    )
    filler = "".join(f"==={m}===\n" for m in markers)
    raw = raw.replace("===SMART===", filler + "===SMART===")

    facts = parse_facts_output(raw)

    assert facts["smart_devices"] is not None
    assert facts["smart_devices"][0]["model"] == "SAMSUNG MZVLB512HBJQ-000L7"
