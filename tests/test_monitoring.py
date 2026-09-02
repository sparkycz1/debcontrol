from __future__ import annotations

from app.ssh.monitoring import parse_monitoring_output


def test_parse_monitoring_output_full():
    raw = (
        "===CPU===\n"
        "23.1\n"
        "===RAM_KB===\n"
        "16332828 6456285\n"
        "===DISKS===\n"
        "/ 45%\n"
        "/boot 12%\n"
        "===FAILED_SERVICES===\n"
        "2\n"
    )

    sample = parse_monitoring_output(raw)

    assert sample["cpu_percent"] == 23.1
    assert sample["ram_total_bytes"] == 16332828 * 1024
    assert sample["ram_used_bytes"] == 6456285 * 1024
    assert sample["disks"] == [
        {"mount": "/", "use_percent": 45},
        {"mount": "/boot", "use_percent": 12},
    ]
    assert sample["failed_services_count"] == 2


def test_parse_monitoring_output_mount_with_spaces():
    raw = "===CPU===\n===RAM_KB===\n===DISKS===\n/mnt/my data 7%\n===FAILED_SERVICES===\n"

    sample = parse_monitoring_output(raw)

    assert sample["disks"] == [{"mount": "/mnt/my data", "use_percent": 7}]


def test_parse_monitoring_output_handles_missing_sections():
    # E.g. no systemd (failed-services count), or a dropped connection.
    sample = parse_monitoring_output("===CPU===\n===RAM_KB===\n")

    assert sample["cpu_percent"] is None
    assert sample["ram_used_bytes"] is None
    assert sample["ram_total_bytes"] is None
    assert sample["disks"] == []
    assert sample["failed_services_count"] is None


def test_parse_monitoring_output_empty_string():
    sample = parse_monitoring_output("")

    assert sample["cpu_percent"] is None
    assert sample["disks"] == []
    assert sample["failed_services_count"] is None


def test_parse_monitoring_output_zero_failed_services_is_not_none():
    # "0" must parse as the integer 0 (genuinely no failed services), not
    # be confused with "couldn't tell" (None).
    raw = "===CPU===\n===RAM_KB===\n===DISKS===\n===FAILED_SERVICES===\n0\n"

    sample = parse_monitoring_output(raw)

    assert sample["failed_services_count"] == 0
