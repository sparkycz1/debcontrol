from __future__ import annotations

from app.ssh.monitoring import parse_monitoring_output


def test_parse_monitoring_output_full():
    raw = (
        "===CPU===\n"
        "23.1\n"
        "===LOAD===\n"
        "0.52 0.58 0.59\n"
        "===RAM_KB===\n"
        "16332828 6456285\n"
        "===NET===\n"
        "eth0 987654321 123456789\n"
        "===DISKIO===\n"
        "sda 102400000 76800000\n"
        "===FILESYSTEMS===\n"
        "/ 107374182400 32212254720 75161927680 30%\n"
        "===FAILED_SERVICES===\n"
        "2\n"
    )

    sample = parse_monitoring_output(raw)

    assert sample["cpu_percent"] == 23.1
    assert (sample["load1"], sample["load5"], sample["load15"]) == (0.52, 0.58, 0.59)
    assert sample["ram_total_bytes"] == 16332828 * 1024
    assert sample["ram_used_bytes"] == 6456285 * 1024
    assert sample["network_io"] == [
        {"iface": "eth0", "rx_bytes": 987654321, "tx_bytes": 123456789}
    ]
    assert sample["disk_io"] == [
        {"device": "sda", "read_bytes": 102400000, "write_bytes": 76800000}
    ]
    assert sample["filesystems"] == [
        {
            "mount": "/",
            "size_bytes": 107374182400,
            "used_bytes": 32212254720,
            "avail_bytes": 75161927680,
            "use_percent": 30,
        }
    ]
    assert sample["failed_services_count"] == 2


def test_parse_monitoring_output_multiple_interfaces_and_disks():
    raw = (
        "===CPU===\n===LOAD===\n===RAM_KB===\n"
        "===NET===\n"
        "eth0 100 200\n"
        "wg0 300 400\n"
        "===DISKIO===\n"
        "sda 1000 2000\n"
        "nvme0n1 3000 4000\n"
        "===FILESYSTEMS===\n"
        "===FAILED_SERVICES===\n"
    )

    sample = parse_monitoring_output(raw)

    assert [n["iface"] for n in sample["network_io"]] == ["eth0", "wg0"]
    assert [d["device"] for d in sample["disk_io"]] == ["sda", "nvme0n1"]


def test_parse_monitoring_output_multiple_filesystems():
    raw = (
        "===CPU===\n===LOAD===\n===RAM_KB===\n===NET===\n===DISKIO===\n"
        "===FILESYSTEMS===\n"
        "/ 1000 500 500 50%\n"
        "/boot 2000 100 1900 5%\n"
        "===FAILED_SERVICES===\n"
    )

    sample = parse_monitoring_output(raw)

    assert [fs["mount"] for fs in sample["filesystems"]] == ["/", "/boot"]
    assert sample["filesystems"][0]["use_percent"] == 50
    assert sample["filesystems"][1]["use_percent"] == 5


def test_parse_monitoring_output_handles_missing_sections():
    sample = parse_monitoring_output("===CPU===\n===LOAD===\n===RAM_KB===\n")

    assert sample["cpu_percent"] is None
    assert sample["load1"] is None
    assert sample["ram_used_bytes"] is None
    assert sample["network_io"] == []
    assert sample["disk_io"] == []
    assert sample["filesystems"] == []
    assert sample["failed_services_count"] is None


def test_parse_monitoring_output_empty_string():
    sample = parse_monitoring_output("")

    assert sample["cpu_percent"] is None
    assert sample["load1"] is None
    assert sample["network_io"] == []
    assert sample["disk_io"] == []
    assert sample["filesystems"] == []
    assert sample["failed_services_count"] is None


def test_parse_monitoring_output_zero_failed_services_is_not_none():
    # "0" must parse as the integer 0 (genuinely no failed services), not
    # be confused with "couldn't tell" (None).
    raw = (
        "===CPU===\n===LOAD===\n===RAM_KB===\n===NET===\n===DISKIO===\n"
        "===FILESYSTEMS===\n===FAILED_SERVICES===\n0\n"
    )

    sample = parse_monitoring_output(raw)

    assert sample["failed_services_count"] == 0
