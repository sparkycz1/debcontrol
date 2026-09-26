"""Security updates: the per-package `security` flag, CVE ids from
changelogs (`app.ssh.security_advisories`), carrying looked-up answers
between checks, and the fleet-wide Security updates page / API."""

from __future__ import annotations

from typing import Any

from app.db.models.machine import AuthMethod, Machine
from app.services.security_updates import build_security_overview
from app.ssh.security_advisories import (
    build_changelog_command,
    build_source_map_command,
    is_safe_package_name,
    parse_changelog,
    parse_source_map,
    split_changelog_output,
)
from app.ssh.updates import carry_over_advisories, parse_apt_upgradable_packages
from tests.test_api_v1_extended import _api_token

CHANGELOG = """\
openssl (3.0.15-1~deb12u1) bookworm-security; urgency=medium

  * Non-maintainer upload by the Security Team.
  * CVE-2024-9143: out-of-bounds memory access
  * Fix CVE-2024-5535 and CVE-2024-9143.

 -- Security Team <team@security.debian.org>  Mon, 21 Oct 2024 10:00:00 +0000

openssl (3.0.14-1~deb12u2) bookworm-security; urgency=high

  * CVE-2024-6119: possible denial of service

 -- Security Team <team@security.debian.org>  Mon, 02 Sep 2024 10:00:00 +0000

openssl (3.0.13-1~deb12u1) bookworm; urgency=medium

  * CVE-2023-0001: already installed, must not be listed

 -- Someone <x@example.org>  Mon, 01 Jan 2024 10:00:00 +0000
"""


def test_apt_parser_flags_security_suites() -> None:
    raw = (
        "===APT_UPGRADABLE===\n"
        "openssl/bookworm-security 3.0.15-1~deb12u1 amd64 [upgradable from: 3.0.13-1~deb12u1]\n"
        "vim/bookworm-updates 2:9.0 amd64 [upgradable from: 2:8.2]\n"
        "===FLATPAK_UPGRADABLE===\n===SNAP_UPGRADABLE===\n"
    )
    packages = parse_apt_upgradable_packages(raw)
    assert [(p["name"], p.get("security")) for p in packages] == [
        ("openssl", True),
        ("vim", False),
    ]


def test_parse_changelog_stops_at_the_installed_version() -> None:
    advisory = parse_changelog(CHANGELOG, "3.0.13-1~deb12u1")
    assert advisory.cves == ["CVE-2024-9143", "CVE-2024-6119", "CVE-2024-5535"]
    assert advisory.urgency == "high"


def test_parse_changelog_handles_binnmu_and_unknown_version() -> None:
    assert "CVE-2023-0001" not in parse_changelog(CHANGELOG, "3.0.13-1~deb12u1+b1").cves
    assert "CVE-2023-0001" in parse_changelog(CHANGELOG, None).cves


def test_split_output_and_failure_marker() -> None:
    raw = (
        "===DEBCONTROL_CHANGELOG=== openssl\nopenssl (2) x; urgency=low\n  * CVE-2026-1\n"
        "===DEBCONTROL_CHANGELOG=== libc6\nglibc (3) x; urgency=high\n"
        "===DEBCONTROL_CHANGELOG_FAILED===\n"
    )
    blocks = split_changelog_output(raw)
    assert set(blocks) == {"openssl", "libc6"}
    assert "CVE-2026-1" in blocks["openssl"]


def test_package_names_are_validated_before_reaching_the_shell() -> None:
    assert is_safe_package_name("libssl3")
    assert is_safe_package_name("libstdc++6:amd64")
    assert not is_safe_package_name("x; rm -rf /")
    assert not is_safe_package_name("$(id)")
    command = build_changelog_command(["openssl", "x; rm -rf /"])
    assert "rm -rf" not in command and "apt-get changelog -q openssl" in command
    assert "rm -rf" not in build_source_map_command(["openssl", "x; rm -rf /"])


def test_source_map_falls_back_to_the_binary_name() -> None:
    assert parse_source_map("libssl3\topenssl\nvim\t\nlibc6:amd64\tglibc\n") == {
        "libssl3": "openssl",
        "vim": "vim",
        "libc6": "glibc",
    }


def test_carry_over_reuses_answers_for_the_same_version_only() -> None:
    previous = [
        {"name": "openssl", "new_version": "2", "security": True, "cves": ["CVE-1"],
         "urgency": "high"},
        {"name": "curl", "new_version": "7", "security": True, "cves": None},
    ]
    current: list[Any] = [
        {"name": "openssl", "current_version": "1", "new_version": "2", "security": True},
        {"name": "curl", "current_version": "6", "new_version": "7", "security": True},
        {"name": "zlib", "current_version": "1", "new_version": "3", "security": True},
        {"name": "vim", "current_version": "8", "new_version": "9", "security": False},
    ]
    missing = carry_over_advisories(current, previous)
    assert current[0]["cves"] == ["CVE-1"] and current[0]["urgency"] == "high"
    # curl was never resolved, zlib is new; vim isn't a security update.
    assert [p["name"] for p in missing] == ["curl", "zlib"]


def _machine(name: str, packages: list[dict[str, Any]]) -> Machine:
    return Machine(
        name=name, ip_address="10.0.0.1", port=22, username="root",
        auth_method=AuthMethod.PASSWORD, apt_upgradable_packages=packages,
        security_upgradable_count=sum(1 for p in packages if p.get("security")),
        is_active=True, os_id="debian",
    )


def test_overview_groups_by_package_and_orders_by_urgency() -> None:
    a = _machine("a", [
        {"name": "openssl", "new_version": "2", "security": True, "cves": ["CVE-2026-0002"],
         "urgency": "medium"},
        {"name": "curl", "new_version": "7", "security": True, "cves": ["CVE-9"],
         "urgency": "high"},
    ])
    b = _machine("b", [
        {"name": "openssl", "new_version": "2", "security": True, "cves": ["CVE-2026-0003"],
         "urgency": "low"},
        {"name": "vim", "new_version": "9", "security": False},
    ])
    rows = build_security_overview([a, b])
    assert [r.package for r in rows] == ["curl", "openssl"]
    openssl = rows[1]
    assert [m.name for m in openssl.machines] == ["a", "b"]
    assert openssl.cves == ["CVE-2026-0003", "CVE-2026-0002"]
    assert openssl.urgency == "medium"


async def test_security_page_and_api(client, db_session_factory) -> None:  # type: ignore[no-untyped-def]
    async with db_session_factory() as session:
        session.add(_machine("web1", [
            {"name": "openssl", "current_version": "1", "new_version": "2", "security": True,
             "cves": ["CVE-2026-0001"], "urgency": "high"},
        ]))
        await session.commit()

    page = await client.get("/machines/security-updates")
    assert page.status_code == 200
    assert "CVE-2026-0001" in page.text
    assert "https://security-tracker.debian.org/tracker/CVE-2026-0001" in page.text

    headers = await _api_token(client)
    api = await client.get("/api/v1/machines/security-updates", headers=headers)
    assert api.status_code == 200, api.text
    (row,) = api.json()
    assert row["package"] == "openssl" and row["machines"][0]["name"] == "web1"


async def test_security_page_respects_group_scope(client, login_as, db_session_factory) -> None:  # type: ignore[no-untyped-def]
    from app.db.models.machine_group import MachineGroup
    from app.db.models.role import Permission

    async with db_session_factory() as session:
        group = MachineGroup(name="other")
        session.add(group)
        await session.flush()
        hidden = _machine("secret-box-7", [
            {"name": "openssl", "new_version": "2", "security": True, "cves": ["CVE-1"]},
        ])
        hidden.group_id = group.id
        session.add(hidden)
        visible_group = MachineGroup(name="mine")
        session.add(visible_group)
        await session.commit()
        visible_group_id = visible_group.id

    await login_as(client, permissions={Permission.MACHINE_VIEW}, group_ids={visible_group_id})
    page = await client.get("/machines/security-updates")
    assert page.status_code == 200
    assert "secret-box-7" not in page.text
