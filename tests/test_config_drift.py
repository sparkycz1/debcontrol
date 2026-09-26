"""Configuration drift and new-security-update detection
(`app.services.config_drift`, the facts additions in `app.ssh.facts`, and
their wiring into the facts refresh / update check jobs)."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select

import app.tasks.jobs as jobs
from app.db.models.machine import AuthMethod, Machine
from app.db.models.machine_change import MachineChange
from app.db.models.notification_rule import NotificationEventType
from app.services import config_drift
from app.ssh.facts import parse_facts_output
from app.ssh.updates import UpdateCheckResult


def test_facts_parse_listening_ports_and_accounts() -> None:
    raw = (
        "===HOSTNAME===\nweb1\n"
        "===NETWORK===\neth0 10.0.0.5/24\n"
        "===LISTEN===\n0.0.0.0:22\n[::]:22\n127.0.0.53%lo:53\n*:80\n0.0.0.0:22\n"
        "===ADMINS===\nalice\nbob\n\nroot\nalice\n"
        "===LOGINS===\nalice\nbob\ndeploy\n"
        "===VIRT===\nkvm\n"
    )
    facts = parse_facts_output(raw)
    assert facts["listening_ports"] == ["0.0.0.0:22", "[::]:22", "127.0.0.53:53", "*:80"]
    assert facts["admin_users"] == ["alice", "bob", "root"]
    assert facts["login_users"] == ["alice", "bob", "deploy"]
    assert facts["is_physical"] is False


def test_facts_without_ss_output_leave_ports_unknown() -> None:
    facts = parse_facts_output("===HOSTNAME===\nweb1\n===LISTEN===\n===ADMINS===\nroot\n")
    assert facts["listening_ports"] is None


def _machine(**fields: Any) -> Machine:
    machine = Machine(
        id=uuid.uuid4(), name="web1", ip_address="10.0.0.5", port=22, username="root",
        auth_method=AuthMethod.PASSWORD,
    )
    for key, value in fields.items():
        setattr(machine, key, value)
    return machine


def test_diff_reports_scalar_and_set_changes() -> None:
    before = config_drift.snapshot(
        _machine(
            kernel_version="6.1.0-25", ram_bytes=8 * 1024**3, listening_ports=["0.0.0.0:22"],
            admin_users=["root"], network_interfaces=[{"interface": "eth0", "address": "a"}],
        )
    )
    after = config_drift.snapshot(
        _machine(
            kernel_version="6.1.0-26", ram_bytes=8 * 1024**3 - 5_000_000,
            listening_ports=["0.0.0.0:22", "0.0.0.0:8080"], admin_users=["root", "deploy"],
            network_interfaces=[{"interface": "eth0", "address": "a"}],
        )
    )
    changes = {c.field: c for c in config_drift.diff_snapshots(before, after)}
    assert set(changes) == {"kernel_version", "listening_ports", "admin_users"}
    assert changes["kernel_version"].old_value == "6.1.0-25"
    assert changes["listening_ports"].new_value == "0.0.0.0:8080"
    assert changes["listening_ports"].old_value is None
    assert changes["admin_users"].describe() == "Admin accounts: +deploy"


def test_unknown_before_or_after_is_not_a_change() -> None:
    before = config_drift.snapshot(_machine(listening_ports=None, kernel_version=None))
    after = config_drift.snapshot(_machine(listening_ports=["0.0.0.0:22"], kernel_version="6"))
    assert config_drift.diff_snapshots(before, after) == []


def test_new_security_packages_needs_a_baseline() -> None:
    current = [
        {"name": "openssl", "new_version": "2", "security": True, "cves": ["CVE-2026-1"]},
        {"name": "vim", "new_version": "9", "security": False},
    ]
    # Never checked, or a list stored before the `security` flag: no baseline.
    assert config_drift.new_security_packages(None, current) == []
    assert config_drift.new_security_packages([{"name": "x", "new_version": "1"}], current) == []
    # A known baseline: only what's new.
    assert config_drift.new_security_packages([], current) == [current[0]]
    same = [{"name": "openssl", "new_version": "2", "security": True}]
    assert config_drift.new_security_packages(same, current) == []


async def _make_machine(db_session_factory, **fields: Any) -> uuid.UUID:  # type: ignore[no-untyped-def]
    async with db_session_factory() as session:
        machine = Machine(
            name="web1", ip_address="10.0.0.5", port=22, username="root",
            auth_method=AuthMethod.PASSWORD, host_key_fingerprint="SHA256:x", **fields,
        )
        session.add(machine)
        await session.commit()
        return machine.id


def _facts(**overrides: Any) -> dict[str, Any]:
    facts: dict[str, Any] = {
        "hostname": "web1", "os_version": "Debian 12", "os_id": "debian",
        "kernel_version": "6.1.0-26", "cpu_architecture": "x86_64", "cpu_cores": 4,
        "cpu_model": "CPU", "ram_bytes": 8 * 1024**3, "ram_speed_mhz": None, "disks": [],
        "reboot_required": False, "uptime_seconds": 10, "process_count": 5, "filesystems": [],
        "network_interfaces": [], "listening_ports": ["0.0.0.0:22", "0.0.0.0:8080"],
        "admin_users": ["root"], "login_users": [], "is_physical": False, "smart_devices": None,
    }
    facts.update(overrides)
    return facts


async def test_facts_refresh_records_changes_and_notifies(db_session_factory, monkeypatch):
    machine_id = await _make_machine(
        db_session_factory, kernel_version="6.1.0-25", listening_ports=["0.0.0.0:22"],
        admin_users=["root"], login_users=[],
    )
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)

    async def _fake_gather(machine: Machine, secret: object, wait: float) -> dict[str, Any]:
        return _facts()

    sent: list[tuple[NotificationEventType, dict[str, Any]]] = []

    async def _fake_notify(db, event_type, **kwargs):
        sent.append((event_type, kwargs.get("context") or {}))

    monkeypatch.setattr(jobs, "gather_facts", _fake_gather)
    monkeypatch.setattr(config_drift, "notify", _fake_notify)

    assert (await jobs._refresh_machine_facts(str(machine_id)))["ok"] is True

    async with db_session_factory() as session:
        rows = (await session.execute(select(MachineChange))).scalars().all()
    assert {row.field for row in rows} == {"kernel_version", "listening_ports"}
    ((event, context),) = sent
    assert event == NotificationEventType.MACHINE_CONFIG_CHANGED
    assert "Kernel: 6.1.0-25 → 6.1.0-26" in context["changes"]

    # A second identical refresh changes nothing.
    sent.clear()
    await jobs._refresh_machine_facts(str(machine_id))
    assert sent == []


async def test_first_refresh_after_upgrade_is_quiet(db_session_factory, monkeypatch):
    machine_id = await _make_machine(db_session_factory, kernel_version="6.1.0-26")
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)

    async def _fake_gather(machine: Machine, secret: object, wait: float) -> dict[str, Any]:
        return _facts()

    sent: list[object] = []

    async def _fake_notify(db, event_type, **kwargs):
        sent.append(event_type)

    monkeypatch.setattr(jobs, "gather_facts", _fake_gather)
    monkeypatch.setattr(config_drift, "notify", _fake_notify)
    await jobs._refresh_machine_facts(str(machine_id))
    assert sent == []


async def test_update_check_announces_new_security_updates(db_session_factory, monkeypatch):
    machine_id = await _make_machine(db_session_factory, apt_upgradable_packages=[])
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)

    async def _fake_check(machine, secret, connect_timeout, run_timeout):
        return UpdateCheckResult(
            exit_status=0, upgradable_count=2, security_upgradable_count=1,
            flatpak_upgradable_count=0, snap_upgradable_count=0, output="",
            apt_upgradable_packages=[
                {"name": "openssl", "current_version": "1", "new_version": "2",
                 "security": True, "cves": ["CVE-2026-0001"], "urgency": "high"},
                {"name": "vim", "current_version": "8", "new_version": "9", "security": False},
            ],
        )

    sent: list[tuple[NotificationEventType, dict[str, Any]]] = []

    async def _fake_notify(db, event_type, **kwargs):
        sent.append((event_type, kwargs.get("context") or {}))

    monkeypatch.setattr(jobs, "check_updates", _fake_check)
    monkeypatch.setattr(config_drift, "notify", _fake_notify)

    assert (await jobs._check_machine_updates(str(machine_id)))["ok"] is True
    ((event, context),) = sent
    assert event == NotificationEventType.SECURITY_UPDATES_AVAILABLE
    assert context["package_count"] == "1"
    assert "CVE-2026-0001" in context["cves"]

    # Still pending on the next check: not announced again.
    sent.clear()
    await jobs._check_machine_updates(str(machine_id))
    assert sent == []
    async with db_session_factory() as session:
        (row,) = (await session.execute(select(MachineChange))).scalars().all()
    assert row.category == "security" and "openssl 2" in (row.new_value or "")
