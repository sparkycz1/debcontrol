from __future__ import annotations

from app.ssh.facts import parse_facts_output


def test_parse_facts_output_full():
    raw = (
        "===HOSTNAME===\n"
        "web1\n"
        "===OS===\n"
        "Debian GNU/Linux 12 (bookworm)\n"
        "===KERNEL===\n"
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


def test_parse_facts_output_empty_string():
    facts = parse_facts_output("")

    assert facts["hostname"] is None
    assert facts["disks"] == []
