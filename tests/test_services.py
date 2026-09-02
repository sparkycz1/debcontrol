from __future__ import annotations

from app.ssh.services import parse_services_output


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
        },
        {
            "unit": "cron.service",
            "load_state": "loaded",
            "active_state": "active",
            "sub_state": "running",
            "description": "Regular background program processing daemon",
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
        }
    ]


def test_parse_services_output_empty_string():
    assert parse_services_output("") == []


def test_parse_services_output_ignores_malformed_lines():
    raw = "not enough fields\nbar.service loaded active running OK\n"

    services = parse_services_output(raw)

    assert len(services) == 1
    assert services[0]["unit"] == "bar.service"
