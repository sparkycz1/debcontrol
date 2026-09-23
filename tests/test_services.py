from __future__ import annotations

from app.ssh.services import SHOW_DELIMITER, parse_services_output

_NO_USAGE = {
    "cpu_usage_nsec": None,
    "memory_bytes": None,
    "memory_peak_bytes": None,
    "active_enter_monotonic": None,
}


def test_parse_services_output_basic():
    raw = (
        "sshd.service                loaded active   running OpenBSD Secure Shell server\n"
        "cron.service                loaded active   running Regular background program "
        "processing daemon\n"
    )

    services = parse_services_output(raw)

    assert services == [
        {
            "unit": "sshd.service",
            "load_state": "loaded",
            "active_state": "active",
            "sub_state": "running",
            "description": "OpenBSD Secure Shell server",
            **_NO_USAGE,
        },
        {
            "unit": "cron.service",
            "load_state": "loaded",
            "active_state": "active",
            "sub_state": "running",
            "description": "Regular background program processing daemon",
            **_NO_USAGE,
        },
    ]


def test_parse_services_output_failed_unit():
    raw = "foo.service loaded failed failed Some Failed Thing\n"

    services = parse_services_output(raw)

    assert services == [
        {
            "unit": "foo.service",
            "load_state": "loaded",
            "active_state": "failed",
            "sub_state": "failed",
            "description": "Some Failed Thing",
            **_NO_USAGE,
        }
    ]


def test_parse_services_output_strips_bullet_prefix():
    # Some systemd versions prefix a failed/masked unit's line with "● "
    # even under --plain.
    raw = "● foo.service loaded failed failed Some Failed Thing\n"

    services = parse_services_output(raw)

    assert services[0]["unit"] == "foo.service"


def test_parse_services_output_no_description():
    raw = "bar.service loaded active running\n"

    services = parse_services_output(raw)

    assert services == [
        {
            "unit": "bar.service",
            "load_state": "loaded",
            "active_state": "active",
            "sub_state": "running",
            "description": "",
            **_NO_USAGE,
        }
    ]


def test_parse_services_output_empty_string():
    assert parse_services_output("") == []


def test_parse_services_output_ignores_malformed_lines():
    raw = "not enough fields\nbar.service loaded active running OK\n"

    services = parse_services_output(raw)

    assert len(services) == 1
    assert services[0]["unit"] == "bar.service"


def test_parse_services_output_reads_cgroup_accounting_for_running_units():
    raw = (
        "sshd.service loaded active running OpenBSD Secure Shell server\n"
        "foo.service loaded failed failed Foo\n"
        f"{SHOW_DELIMITER}\n"
        "Id=sshd.service\n"
        "CPUUsageNSec=1500000000\n"
        "MemoryCurrent=10485760\n"
        "MemoryPeak=[not set]\n"
        "ActiveEnterTimestampMonotonic=123456\n"
        "\n"
    )

    sshd, foo = parse_services_output(raw)

    assert sshd["cpu_usage_nsec"] == 1_500_000_000
    assert sshd["memory_bytes"] == 10_485_760
    assert sshd["memory_peak_bytes"] is None
    assert sshd["active_enter_monotonic"] == 123456
    assert foo["cpu_usage_nsec"] is None


def test_parse_services_output_treats_uint64_max_as_unset():
    raw = (
        "a.service loaded active running A\n"
        f"{SHOW_DELIMITER}\n"
        "Id=a.service\n"
        "MemoryCurrent=18446744073709551615\n"
    )

    (entry,) = parse_services_output(raw)

    assert entry["memory_bytes"] is None
