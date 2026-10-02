"""The 0.78.0 homelab/Proxmox round: SSH connection reuse and the root sudo
shim, the journal's structured read and own-session filter, Proxmox/ZFS
parsing, ARC-aware memory, update strategies/holds/changelogs, scheduling
time zones, rolling updates, push channels, health events, ping/TCP/DNS
checks and the machines' SLA rows."""

from __future__ import annotations

import asyncio
import json
import struct
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select

from app.db.models.machine import AuthMethod, Machine
from app.db.models.machine_reachability_sample import MachineReachabilitySample
from app.db.models.machine_update_run import MachineUpdateRun, UpgradeStrategy
from app.db.models.maintenance_window import MaintenanceWindow
from app.db.models.notification_log import NotificationDeliveryChannel
from app.db.models.scheduled_task import ScheduledTask, ScheduleTargetType
from app.scheduling.cron import next_runs
from app.scheduling.jobs import _run_scheduled_task
from app.services import health_events, network_probes, push_channels
from app.services.endpoint_sla import load_sla_report
from app.services.machine_actions import trigger_updates
from app.ssh import logs as ssh_logs
from app.ssh import pool, proxmox
from app.ssh.facts import parse_facts_output
from app.ssh.monitoring import parse_monitoring_output
from app.ssh.shell import ROOT_SUDO_SHIM, with_root_shim
from app.ssh.updates import (
    build_hold_command,
    build_update_command,
    changelog_since,
    parse_held_packages,
    reboot_hint_packages,
)
from app.web import charts


def _machine(**overrides: Any) -> Machine:
    values: dict[str, Any] = {
        "id": uuid.uuid4(),
        "name": "pve1",
        "ip_address": "10.0.0.5",
        "port": 22,
        "username": "root",
        "auth_method": AuthMethod.PASSWORD,
        "host_key_fingerprint": "SHA256:x",
    }
    values.update(overrides)
    return Machine(**values)


async def _add_machine(db_session_factory: Any, **overrides: Any) -> uuid.UUID:
    async with db_session_factory() as db:
        machine = _machine(**overrides)
        db.add(machine)
        await db.commit()
        return machine.id


# --- SSH: root shim and connection reuse ---------------------------------------


def test_root_shim_only_defines_sudo_for_uid_zero():
    command = with_root_shim("sudo -n smartctl -H /dev/sda")
    assert command.startswith(ROOT_SUDO_SHIM)
    assert 'if [ "$(id -u)" = 0 ]; then sudo()' in ROOT_SUDO_SHIM
    assert command.endswith("sudo -n smartctl -H /dev/sda")


class _FakeConn:
    def __init__(self) -> None:
        self.closed = False
        self.commands: list[str] = []

    def is_closed(self) -> bool:
        return self.closed

    def close(self) -> None:
        self.closed = True

    async def run(self, command: str, **kwargs: Any) -> Any:
        self.commands.append(command)
        return type("R", (), {"exit_status": 0, "stdout": ""})()

    async def __aenter__(self) -> _FakeConn:
        return self

    async def __aexit__(self, *exc: object) -> bool:
        self.close()
        return False


async def test_connections_are_reused_on_the_worker_loop(monkeypatch):
    opened: list[_FakeConn] = []

    async def fake_open(machine: object, secret: object, timeout_seconds: int) -> _FakeConn:
        conn = _FakeConn()
        opened.append(conn)
        return conn

    async def fifteen_minutes() -> float:
        return 900.0

    monkeypatch.setattr(pool, "open_connection", fake_open)
    monkeypatch.setattr(pool, "_idle_seconds", fifteen_minutes)
    pool.enable_for_loop(asyncio.get_running_loop())
    try:
        machine = _machine()
        async with pool.machine_connection(machine, "pw", 5) as first:
            await first.run("uptime")
        async with pool.machine_connection(machine, "pw", 5) as second:
            await second.run("uptime")
        assert len(opened) == 1 and first is second
        assert not opened[0].closed
        # A different credential never reuses the old login.
        async with pool.machine_connection(machine, "other", 5):
            pass
        assert len(opened) == 2 and opened[0].closed
    finally:
        pool.reset()


async def test_without_the_worker_loop_every_use_connects_afresh(monkeypatch):
    opened: list[_FakeConn] = []

    async def fake_open(machine: object, secret: object, timeout_seconds: int) -> _FakeConn:
        conn = _FakeConn()
        opened.append(conn)
        return conn

    monkeypatch.setattr(pool, "open_connection", fake_open)
    pool.reset()
    machine = _machine()
    for _ in range(2):
        async with pool.machine_connection(machine, "pw", 5):
            pass
    assert len(opened) == 2 and all(c.closed for c in opened)


# --- Journal -----------------------------------------------------------------------


def test_journal_command_unit_boot_and_structured_output():
    command = ssh_logs.build_journal_command(
        lines=100, search="", since="", until="", unit="nginx.service", boot="-1", structured=True
    )
    assert "-u nginx.service" in command and "-b -1" in command
    assert "-o json" in command and command.startswith('echo "@@SELF')
    bad = ssh_logs.build_journal_command(
        lines=10, search="", since="", until="", unit="x; rm -rf /", boot="7"
    )
    assert "-u" not in bad and "-b" not in bad


def _entry(**fields: str) -> str:
    return json.dumps({"__REALTIME_TIMESTAMP": "1700000000000000", **fields})


def test_own_sessions_are_hidden_from_the_journal():
    raw = "\n".join(
        [
            "@@SELF 0 172.18.0.5",
            _entry(SYSLOG_IDENTIFIER="sshd", _PID="100",
                   MESSAGE="Accepted publickey for root from 172.18.0.5 port 4242 ssh2"),
            _entry(SYSLOG_IDENTIFIER="sshd", _PID="100",
                   MESSAGE="pam_unix(sshd:session): session opened for user root"),
            _entry(SYSLOG_IDENTIFIER="systemd-logind", _PID="1", SESSION_ID="7", LEADER="100",
                   MESSAGE="New session 7 of user root."),
            _entry(SYSLOG_IDENTIFIER="systemd", _PID="1", UNIT="session-7.scope",
                   MESSAGE="Started session-7.scope."),
            _entry(SYSLOG_IDENTIFIER="systemd", _PID="1", UNIT="user@0.service",
                   MESSAGE="Started user@0.service."),
            _entry(SYSLOG_IDENTIFIER="sshd", _PID="200",
                   MESSAGE="Accepted password for admin from 192.168.1.20 port 5000 ssh2"),
            _entry(SYSLOG_IDENTIFIER="kernel", PRIORITY="3", MESSAGE="disk error"),
        ]
    )
    entries, uid, address = ssh_logs.parse_journal_json(raw)
    assert (uid, address) == ("0", "172.18.0.5")
    kept, hidden = ssh_logs.filter_own_sessions(
        entries, own_uid=uid, own_address=address, username="root"
    )
    assert hidden == 5
    assert [e.message for e in kept] == [
        "Accepted password for admin from 192.168.1.20 port 5000 ssh2",
        "disk error",
    ]
    assert kept[1].priority == 3


# --- Proxmox / ZFS / memory ------------------------------------------------------------


def test_proxmox_inventory_and_reboot_detection_from_facts():
    raw = (
        "===KERNEL===\n6.8.12-4-pve\n"
        "===KERNEL_LATEST===\n6.8.12-5-pve\n"
        "===REBOOT_FLAG===\n"
        "===PVE_VERSION===\npve-manager/8.3.1/abc (running kernel: 6.8.12-4-pve)\n"
        '===PVE_STORAGE===\n[{"storage":"pbs","type":"pbs","active":1,"total":100,"used":25}]\n'
        '===PVE_BACKUP_TASKS===\n[{"status":"ERROR: timeout","starttime":10,"id":"101"}]\n'
        '===PVE_BACKUP_JOBS===\n[{"id":"b1","schedule":"21:00","all":1,"storage":"pbs"}]\n'
        '===PVE_NOT_BACKED_UP===\n[{"vmid":105,"name":"scratch","type":"lxc"}]\n'
    )
    facts = parse_facts_output(raw)
    assert facts["reboot_required"] is True
    assert facts["pve_version"] == "8.3.1"
    assert facts["pve_storage"] is not None and facts["pve_storage"][0]["used_percent"] == 25.0
    assert facts["pve_backups"] is not None
    assert facts["pve_backups"]["tasks"][0]["ok"] is False
    assert facts["pve_backups"]["not_backed_up"][0]["vmid"] == 105
    assert parse_facts_output("===REBOOT_FLAG===\nyes\n")["reboot_required"] is True


def test_monitoring_subtracts_the_arc_and_lists_failed_units():
    gib = 1024 * 1024
    raw = (
        f"===RAM_KB===\n{64 * gib} {60 * gib} {2 * gib}\n"
        f"===ZFS_ARC===\n{40 * gib * 1024}\n"
        "===FAILED_SERVICES===\n@@OK\nnginx.service\nbackup.service\n"
        "===ZFS_POOLS===\nrpool\t100\t50\t50\t10\t50\tDEGRADED\n"
        "===ZFS_STATUS===\n  pool: rpool\n state: DEGRADED\nstatus: A disk is gone.\n"
        '===PVE_GUESTS===\n[{"vmid":100,"type":"qemu","status":"running","name":"web"}]\n'
    )
    sample = parse_monitoring_output(raw)
    assert sample["ram_arc_bytes"] == 40 * gib * 1024
    assert sample["ram_used_bytes"] == 20 * gib * 1024
    assert sample["ram_cache_bytes"] == 2 * gib * 1024
    assert sample["failed_units"] == ["backup.service", "nginx.service"]
    assert sample["failed_services_count"] == 2
    assert sample["zfs_pools"] is not None and sample["zfs_pools"][0]["status"] == "A disk is gone."
    assert proxmox.guest_counts(sample["pve_guests"]) == (1, 1)
    assert proxmox.unhealthy_pools(sample["zfs_pools"]) == ["rpool"]


async def test_proxmox_tab_and_overview_strip(client, db_session_factory):
    machine_id = await _add_machine(
        db_session_factory,
        pve_version="8.3.1",
        pve_guests=proxmox.parse_guests(
            '[{"vmid":100,"name":"web","type":"qemu","status":"running","cpu":0.1}]'
        ),
        zfs_pools=proxmox.parse_zfs_pools("rpool	100	50	50	1	50	ONLINE", ""),
        pve_backups=proxmox.parse_backups(
            '[{"status":"OK","starttime":1700000000,"endtime":1700000100}]',
            '[{"id":"b1","schedule":"21:00","all":1,"storage":"pbs"}]',
            '[{"vmid":105,"name":"x","type":"lxc"}]',
        ),
    )
    page = await client.get(f"/machines/{machine_id}/proxmox")
    overview = await client.get(f"/machines/{machine_id}")
    assert page.status_code == 200 and "web" in page.text
    assert "Proxmox VE 8.3.1" in overview.text
    plain = await _add_machine(db_session_factory, name="plain", ip_address="10.0.0.6")
    assert (
        await client.get(f"/machines/{plain}/proxmox", follow_redirects=False)
    ).status_code == 303


# --- Updates --------------------------------------------------------------------------


def test_update_strategies_and_holds():
    assert " upgrade" in build_update_command(UpgradeStrategy.UPGRADE)
    security = build_update_command(UpgradeStrategy.SECURITY)
    assert "install --only-upgrade $pkgs" in security and "-security" in security
    assert "apt-mark hold 'bad name'" in build_hold_command("bad name", hold=True)
    raw = "x\n===APT_UPGRADABLE===\n===FLATPAK_UPGRADABLE===\n===SNAP_UPGRADABLE===\n"
    assert parse_held_packages(raw) is None
    assert parse_held_packages(raw + "===APT_HELD===\nzfsutils-linux\n") == ["zfsutils-linux"]
    assert reboot_hint_packages([{"name": "proxmox-kernel-6.8"}, {"name": "pve-manager"}]) == (
        ["proxmox-kernel-6.8"],
        ["pve-manager"],
    )
    changelog = "p (2) x; urgency=low\n\n  * new\n\np (1) x; urgency=low\n\n  * old\n"
    assert changelog_since(changelog, "1") == "p (2) x; urgency=low\n\n  * new"


async def test_hold_rejects_an_invalid_package_name(client, db_session_factory):
    machine_id = await _add_machine(db_session_factory)
    await client.get(f"/machines/{machine_id}/updates")
    response = await client.post(
        f"/machines/{machine_id}/updates/hold",
        data={"csrf_token": client.cookies.get("csrftoken"), "package": "a;b", "hold": "1"},
        follow_redirects=False,
    )
    assert response.status_code == 303 and "hold_error=" in response.headers["location"]


# --- Scheduling -------------------------------------------------------------------------


def test_cron_follows_the_task_time_zone_across_dst():
    runs = next_runs("0 3 * * *", 3, datetime(2026, 10, 23, 12, tzinfo=UTC), "Europe/Prague")
    assert [r.hour for r in runs] == [1, 2, 2]


async def test_rolling_updates_start_one_machine(db_session_factory, celery_calls):
    ids = [
        await _add_machine(db_session_factory, name=f"m{i}", ip_address=f"10.0.1.{i}")
        for i in range(3)
    ]
    async with db_session_factory() as db:
        machines = list(
            (await db.execute(select(Machine).where(Machine.id.in_(ids)))).scalars().all()
        )
        await trigger_updates(
            db, machines, UpgradeStrategy.FULL_UPGRADE, reboot_if_required=True, rolling=True
        )
        runs = list((await db.execute(select(MachineUpdateRun))).scalars().all())
    assert sorted(r.rollout_position for r in runs) == [0, 1, 2]
    assert all(r.reboot_if_required for r in runs)
    started = [c for c in celery_calls if c[0] == "app.tasks.jobs.run_machine_update"]
    assert len(started) == 1


async def test_a_task_limited_to_maintenance_windows_skips_the_rest(
    db_session_factory, celery_calls, monkeypatch
):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    await _add_machine(db_session_factory)
    async with db_session_factory() as db:
        task = ScheduledTask(
            name="updates in the window",
            action="check_updates",
            target_type=ScheduleTargetType.ALL_MACHINES,
            cron_expression="0 3 * * *",
            timezone="Europe/Prague",
            require_maintenance_window=True,
        )
        db.add(task)
        await db.commit()
        task_id = task.id
    result = await _run_scheduled_task(str(task_id))
    assert result["attempted"] == 0
    now = datetime.now(UTC)
    async with db_session_factory() as db:
        db.add(
            MaintenanceWindow(
                name="now",
                starts_at=now - timedelta(minutes=1),
                ends_at=now + timedelta(hours=1),
                all_machines=True,
            )
        )
        await db.commit()
    assert (await _run_scheduled_task(str(task_id)))["attempted"] == 1


async def test_schedule_form_offers_time_zones(client):
    response = await client.get("/scheduling/new")
    assert 'name="timezone"' in response.text and "Europe/Prague" in response.text
    assert 'name="require_maintenance_window"' in response.text


# --- Notifications ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("channel", "url", "token", "recipient", "expected_url"),
    [
        ("ntfy", "https://ntfy.sh/homelab", None, None, "https://ntfy.sh/"),
        ("gotify", "https://gotify.lan/", "tok", None, "https://gotify.lan/message"),
        ("telegram", None, "123:abc", "42", "https://api.telegram.org/bot123:abc/sendMessage"),
        ("discord", "https://discord.com/api/webhooks/1/x", None, None,
         "https://discord.com/api/webhooks/1/x"),
        ("pushover", None, "apptoken", "userkey", "https://api.pushover.net/1/messages.json"),
        ("mattermost", "https://chat.lan/hooks/abc", None, None, "https://chat.lan/hooks/abc"),
        ("slack", "https://hooks.slack.com/services/T/B/x", None, None,
         "https://hooks.slack.com/services/T/B/x"),
        ("teams", "https://prod.westeurope.logic.azure.com/workflows/x", None, None,
         "https://prod.westeurope.logic.azure.com/workflows/x"),
    ],
)
def test_push_requests(channel, url, token, recipient, expected_url):
    target, kwargs = push_channels.build_request(
        channel, url=url, token=token, recipient=recipient, subject="Příliš", body="žluťoučký"
    )
    assert target == expected_url
    assert "Příliš" in json.dumps(kwargs, ensure_ascii=False)


def test_chat_payload_shapes():
    _url, mattermost = push_channels.build_request(
        "mattermost", url="https://m/h", token=None, recipient=None, subject="S", body="B"
    )
    assert mattermost["json"] == {"text": "**S**\nB"}
    _url, slack = push_channels.build_request(
        "slack", url="https://s/h", token=None, recipient=None, subject="S", body="B"
    )
    assert slack["json"] == {"text": "*S*\nB"}
    _url, teams = push_channels.build_request(
        "teams", url="https://t/h", token=None, recipient=None, subject="S", body="B"
    )
    attachment = teams["json"]["attachments"][0]
    assert attachment["contentType"] == "application/vnd.microsoft.card.adaptive"
    assert [block["text"] for block in attachment["content"]["body"]] == ["S", "B"]
    with pytest.raises(ValueError, match="URL"):
        push_channels.build_request(
            "slack", url=None, token=None, recipient=None, subject="S", body="B"
        )


def test_push_requests_need_their_settings():
    with pytest.raises(ValueError):
        push_channels.build_request(
            "telegram", url=None, token=None, recipient="1", subject="s", body="b"
        )


async def test_ntfy_rule_via_the_form(client, db_session_factory):
    from app.db.models.notification_rule import NotificationRule

    await client.get("/notifications/rules/new")
    response = await client.post(
        "/notifications/rules",
        data={
            "csrf_token": client.cookies.get("csrftoken"),
            "name": "phone",
            "enabled": "on",
            "event_types": ["machine.reboot_required"],
            "delivery_channel": NotificationDeliveryChannel.NTFY.value,
            "webhook_url": "https://ntfy.sh/homelab",
            "channel_token": "tk_secret",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    async with db_session_factory() as db:
        rule = (await db.execute(select(NotificationRule))).scalar_one()
        assert rule.channel_token_encrypted and b"tk_secret" not in rule.channel_token_encrypted


def test_health_transitions_fire_once():
    assert health_events.became_reboot_required(False, True)
    assert not health_events.became_reboot_required(None, True)
    assert health_events.newly_failed_units(["a"], ["a", "b"]) == ["b"]
    assert health_events.newly_failed_units(None, ["a"]) == []
    assert health_events.newly_failing_disks(
        [{"device": "sda", "healthy": True}], [{"device": "sda", "healthy": False}]
    ) == ["sda"]
    assert health_events.newly_unhealthy_pools(
        [{"name": "rpool", "health": "ONLINE"}], [{"name": "rpool", "health": "DEGRADED"}]
    )[0]["name"] == "rpool"
    assert health_events.disk_full_crossed(
        {"/": {"days_until_full": 30}}, {"/": {"days_until_full": 5}}
    ) == ("/", 5.0)
    assert health_events.disk_full_crossed(
        {"/": {"days_until_full": 6}}, {"/": {"days_until_full": 5}}
    ) is None
    assert health_events.new_failed_backups(
        {"tasks": []}, {"tasks": [{"started_at": 1, "id": "", "ok": False, "status": "ERROR"}]}
    )


# --- Checks and SLA -----------------------------------------------------------------------


def test_dns_packet_round_trip():
    query = network_probes.build_dns_query("nas.lan", 1, 4242)
    answer_name = b"\xc0\x0c"
    answer = answer_name + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([192, 168, 1, 10])
    response = struct.pack("!HHHHHH", 4242, 0x8180, 1, 1, 0, 0) + query[12:] + answer
    assert network_probes.parse_dns_answers(response, 4242) == (0, ["192.168.1.10"])
    with pytest.raises(ValueError):
        network_probes.parse_dns_answers(response, 1)


async def test_sla_report_includes_machines(db_session_factory):
    machine_id = await _add_machine(db_session_factory)
    now = datetime.now(UTC)
    async with db_session_factory() as db:
        for minutes, reachable in ((3, True), (2, False), (1, True)):
            db.add(
                MachineReachabilitySample(
                    machine_id=machine_id,
                    checked_at=now - timedelta(minutes=minutes),
                    reachable=reachable,
                )
            )
        await db.commit()
        machine = await db.get(Machine, machine_id)
        assert machine is not None
        report = await load_sla_report(
            db, None, machines=[machine], reachability_interval_seconds=60
        )
    row = report.machine_rows[0]
    assert (row.kind, row.probes, row.up, row.outages, row.downtime_seconds) == (
        "ssh", 3, 2, 1, 60
    )


def test_chart_noise_defaults():
    assert charts.noise_interfaces(["eno1", "vmbr0", "tap100i0", "veth101i0", "fwbr100i0"]) == {
        "tap100i0",
        "veth101i0",
        "fwbr100i0",
    }
    assert charts.secondary_sensors(["k10temp Tctl", "nvme Composite", "acpitz temp1"]) == {
        "acpitz temp1"
    }
    assert charts.secondary_sensors(["acpitz temp1"]) == set()
    chart = charts.build_chart(
        [("a", [1.0]), ("b", [2.0])], [datetime(2026, 1, 1, tzinfo=UTC)], hidden=["b"]
    )
    assert chart.data["h"] == [1] and chart.hidden_count == 1
