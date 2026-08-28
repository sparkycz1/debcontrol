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
        "===CPU===\n"
        "4\n"
        "===RAM_KB===\n"
        "8058000\n"
        "===DISKS===\n"
        "sda 500107862016\n"
        "vda 21474836480\n"
    )

    facts = parse_facts_output(raw)

    assert facts["hostname"] == "web1"
    assert facts["os_version"] == "Debian GNU/Linux 12 (bookworm)"
    assert facts["kernel_version"] == "6.1.0-13-amd64"
    assert facts["cpu_cores"] == 4
    assert facts["ram_bytes"] == 8058000 * 1024
    assert facts["disks"] == [
        {"name": "sda", "size_bytes": 500107862016},
        {"name": "vda", "size_bytes": 21474836480},
    ]
    # Running kernel matches the latest installed kernel package.
    assert facts["reboot_required"] is False


def test_parse_facts_output_reboot_required_when_kernel_differs():
    raw = (
        "===HOSTNAME===\nweb1\n"
        "===OS===\nDebian GNU/Linux 12 (bookworm)\n"
        "===KERNEL===\n6.1.0-13-amd64\n"
        "===KERNEL_LATEST===\n6.1.0-18-amd64\n"
        "===CPU===\n4\n"
        "===RAM_KB===\n8058000\n"
        "===DISKS===\n"
    )

    facts = parse_facts_output(raw)

    assert facts["kernel_version"] == "6.1.0-13-amd64"
    assert facts["reboot_required"] is True


def test_parse_facts_output_reboot_unknown_without_kernel_latest():
    # E.g. no dpkg / no linux-image-* packages found (some minimal images).
    # Every `echo ===X===` marker always runs even when the command after it
    # produces nothing, so a real transcript never skips a section outright.
    raw = "===HOSTNAME===\nweb1\n===OS===\n===KERNEL===\n6.1.0-13-amd64\n===KERNEL_LATEST===\n"

    facts = parse_facts_output(raw)

    assert facts["kernel_version"] == "6.1.0-13-amd64"
    assert facts["reboot_required"] is None


def test_parse_facts_output_handles_missing_sections():
    # E.g. a connection that drops mid-way, or commands that aren't present.
    raw = "===HOSTNAME===\nweb1\n===OS===\n"

    facts = parse_facts_output(raw)

    assert facts["hostname"] == "web1"
    assert facts["os_version"] is None
    assert facts["kernel_version"] is None
    assert facts["cpu_cores"] is None
    assert facts["ram_bytes"] is None
    assert facts["disks"] == []
    assert facts["reboot_required"] is None


def test_parse_facts_output_empty_string():
    facts = parse_facts_output("")

    assert facts["hostname"] is None
    assert facts["disks"] == []
    assert facts["reboot_required"] is None
