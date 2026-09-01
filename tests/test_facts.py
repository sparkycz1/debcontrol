from __future__ import annotations

from app.ssh.facts import parse_facts_output


def test_parse_facts_output_full_no_reboot_needed():
    raw = (
        "===HOSTNAME===\n"
        "web1\n"
        "===OS===\n"
        "Debian GNU/Linux 12 (bookworm)\n"
        "===KERNEL===\n"
        "6.1.0-13-amd64\n"
        "===KERNEL_LATEST===\n"
        "6.1.0-13-amd64\n"
        "===ARCH===\n"
        "x86_64\n"
        "===CPU===\n"
        "4\n"
        "===CPU_MODEL===\n"
        "Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz\n"
        "===RAM_KB===\n"
        "8058000\n"
        "===RAM_SPEED===\n"
        "2400\n"
        "===DISKS===\n"
        "sda 500107862016\n"
        "vda 21474836480\n"
        "===UPTIME===\n"
        "123456\n"
        "===PROCESSES===\n"
        "187\n"
        "===FILESYSTEMS===\n"
        "/ 21474836480 10737418240 9663676416 51%\n"
        "/boot 536870912 107374182 407896228 21%\n"
        "===NETWORK===\n"
        "eth0 192.168.1.10/24\n"
        "wg0 10.0.0.5/32\n"
    )

    facts = parse_facts_output(raw)

    assert facts["hostname"] == "web1"
    assert facts["os_version"] == "Debian GNU/Linux 12 (bookworm)"
    assert facts["kernel_version"] == "6.1.0-13-amd64"
    assert facts["cpu_architecture"] == "x86_64"
    assert facts["cpu_cores"] == 4
    assert facts["cpu_model"] == "Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz"
    assert facts["ram_bytes"] == 8058000 * 1024
    assert facts["ram_speed_mhz"] == 2400
    assert facts["disks"] == [
        {"name": "sda", "size_bytes": 500107862016},
        {"name": "vda", "size_bytes": 21474836480},
    ]
    # Running kernel matches the latest installed kernel package.
    assert facts["reboot_required"] is False
    assert facts["uptime_seconds"] == 123456
    assert facts["process_count"] == 187
    assert facts["filesystems"] == [
        {
            "mount": "/",
            "size_bytes": 21474836480,
            "used_bytes": 10737418240,
            "avail_bytes": 9663676416,
            "use_percent": 51,
        },
        {
            "mount": "/boot",
            "size_bytes": 536870912,
            "used_bytes": 107374182,
            "avail_bytes": 407896228,
            "use_percent": 21,
        },
    ]
    assert facts["network_interfaces"] == [
        {"interface": "eth0", "address": "192.168.1.10/24"},
        {"interface": "wg0", "address": "10.0.0.5/32"},
    ]


def test_parse_facts_output_reboot_required_when_kernel_differs():
    raw = (
        "===HOSTNAME===\nweb1\n"
        "===OS===\nDebian GNU/Linux 12 (bookworm)\n"
        "===KERNEL===\n6.1.0-13-amd64\n"
        "===KERNEL_LATEST===\n6.1.0-18-amd64\n"
        "===ARCH===\nx86_64\n"
        "===CPU===\n4\n"
        "===CPU_MODEL===\n"
        "===RAM_KB===\n8058000\n"
        "===RAM_SPEED===\n"
        "===DISKS===\n"
        "===UPTIME===\n999\n"
        "===PROCESSES===\n120\n"
        "===FILESYSTEMS===\n"
        "===NETWORK===\n"
    )

    facts = parse_facts_output(raw)

    assert facts["kernel_version"] == "6.1.0-13-amd64"
    assert facts["reboot_required"] is True


def test_parse_facts_output_reboot_unknown_without_kernel_latest():
    # E.g. no dpkg / no linux-image-* packages found (some minimal images).
    # Every `echo ===X===` marker always runs even when the command after it
    # produces nothing, so a real transcript never skips a section outright.
    raw = (
        "===HOSTNAME===\nweb1\n===OS===\n===KERNEL===\n6.1.0-13-amd64\n"
        "===KERNEL_LATEST===\n===ARCH===\naarch64\n===CPU===\n===CPU_MODEL===\n"
        "===RAM_KB===\n===RAM_SPEED===\n"
        "===DISKS===\n===UPTIME===\n===PROCESSES===\n===FILESYSTEMS===\n===NETWORK===\n"
    )

    facts = parse_facts_output(raw)

    assert facts["kernel_version"] == "6.1.0-13-amd64"
    assert facts["reboot_required"] is None
    assert facts["cpu_architecture"] == "aarch64"
    assert facts["uptime_seconds"] is None
    assert facts["process_count"] is None
    assert facts["filesystems"] == []
    assert facts["network_interfaces"] == []


def test_parse_facts_output_handles_missing_sections():
    # E.g. a connection that drops mid-way, or commands that aren't present.
    raw = "===HOSTNAME===\nweb1\n===OS===\n"

    facts = parse_facts_output(raw)

    assert facts["hostname"] == "web1"
    assert facts["os_version"] is None
    assert facts["kernel_version"] is None
    assert facts["cpu_architecture"] is None
    assert facts["cpu_cores"] is None
    assert facts["ram_bytes"] is None
    assert facts["disks"] == []
    assert facts["reboot_required"] is None
    assert facts["uptime_seconds"] is None
    assert facts["process_count"] is None
    assert facts["filesystems"] == []
    assert facts["network_interfaces"] == []


def test_parse_facts_output_empty_string():
    facts = parse_facts_output("")

    assert facts["hostname"] is None
    assert facts["disks"] == []
    assert facts["reboot_required"] is None
    assert facts["cpu_architecture"] is None
    assert facts["uptime_seconds"] is None
    assert facts["process_count"] is None
    assert facts["filesystems"] == []
    assert facts["network_interfaces"] == []


def test_parse_facts_output_filesystems_ignores_malformed_lines():
    raw = (
        "===HOSTNAME===\nweb1\n===OS===\n===KERNEL===\n===KERNEL_LATEST===\n===ARCH===\n"
        "===CPU===\n===CPU_MODEL===\n===RAM_KB===\n===RAM_SPEED===\n"
        "===DISKS===\n===UPTIME===\n===PROCESSES===\n"
        "===FILESYSTEMS===\n"
        "not enough fields\n"
        "/ 100 50 50 50%\n"
        "===NETWORK===\n"
    )

    facts = parse_facts_output(raw)

    assert facts["filesystems"] == [
        {
            "mount": "/",
            "size_bytes": 100,
            "used_bytes": 50,
            "avail_bytes": 50,
            "use_percent": 50,
        }
    ]
