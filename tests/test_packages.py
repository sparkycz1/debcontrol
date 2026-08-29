from __future__ import annotations

from app.ssh.packages import PackageSource, parse_packages_output


def test_parse_packages_output_apt_only():
    raw = (
        "===APT===\n"
        "bash\t5.2.15-2\n"
        "coreutils\t9.1-1\n"
        "===FLATPAK===\n"
        "===SNAP===\n"
    )

    packages = parse_packages_output(raw)

    assert packages == [
        {"source": PackageSource.APT, "name": "bash", "version": "5.2.15-2"},
        {"source": PackageSource.APT, "name": "coreutils", "version": "9.1-1"},
    ]


def test_parse_packages_output_all_three_sources():
    raw = (
        "===APT===\n"
        "bash\t5.2.15-2\n"
        "===FLATPAK===\n"
        "org.mozilla.firefox\t128.0\n"
        "===SNAP===\n"
        "core22\t20240301\n"
    )

    packages = parse_packages_output(raw)

    assert packages == [
        {"source": PackageSource.APT, "name": "bash", "version": "5.2.15-2"},
        {"source": PackageSource.FLATPAK, "name": "org.mozilla.firefox", "version": "128.0"},
        {"source": PackageSource.SNAP, "name": "core22", "version": "20240301"},
    ]


def test_parse_packages_output_flatpak_and_snap_not_installed():
    # `command -v flatpak`/`command -v snap` guards produce an empty section
    # rather than an error when neither is present.
    raw = "===APT===\nbash\t5.2.15-2\n===FLATPAK===\n===SNAP===\n"

    packages = parse_packages_output(raw)

    assert packages == [{"source": PackageSource.APT, "name": "bash", "version": "5.2.15-2"}]


def test_parse_packages_output_ignores_malformed_lines():
    raw = "===APT===\nbash\t5.2.15-2\nno-tab-here\n\t\n===FLATPAK===\n===SNAP===\n"

    packages = parse_packages_output(raw)

    assert packages == [{"source": PackageSource.APT, "name": "bash", "version": "5.2.15-2"}]


def test_parse_packages_output_empty_string():
    assert parse_packages_output("") == []
