"""The machine Overview's live part (`app.services.live_overview`,
`app.web.routes.machines_live`): cards from the newest samples, the top
processes and one process read on demand, signalling one, and the
connectivity test — plus the readings behind them (`app.ssh.processes`,
`app.ssh.connectivity`, the new monitoring sections)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select

from app.db.models.audit_log import AuditLogEntry, AuditOutcome
from app.db.models.machine import AuthMethod, Machine
from app.db.models.machine_monitoring_sample import MachineMonitoringSample
from app.services import live_overview
from app.ssh import connectivity, processes
from app.ssh.monitoring import parse_monitoring_output, parse_network_links

NOW = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)


def _machine(**kwargs: Any) -> Machine:
    return Machine(
        name="pve1",
        ip_address="10.0.0.5",
        port=22,
        username="root",
        auth_method=AuthMethod.PASSWORD,
        host_key_fingerprint="SHA256:abc",
        **kwargs,
    )


def _sample(machine_id: uuid.UUID, minutes_ago: int, **kwargs: Any) -> MachineMonitoringSample:
    return MachineMonitoringSample(
        machine_id=machine_id, sampled_at=NOW - timedelta(minutes=minutes_ago), **kwargs
    )


# --- Readings -------------------------------------------------------------------


def test_cpu_split_network_counters_and_links_are_read() -> None:
    raw = (
        "===CPU===\n40.0 30.0 8.0 2.0\n"
        "===NET===\neth0 1000 2000 1 2 3 4\nveth1 5 6\n"
        "===NETLINKS===\n"
        "eno1\tphysical\tup\t1000\tbond0\t1500\n"
        "bond0\tbond\tup\t2000\tvmbr0\t1500\n"
        "vmbr0\tbridge\tup\t\t\t1500\n"
        "wlp2s0\twireless\tdown\t-1\t\t1500\n"
        "tap100i0\tsomething\tunknown\t\tvmbr0\t1500\n"
        "garbage line\n"
    )
    sample = parse_monitoring_output(raw)

    assert sample["cpu_percent"] == 40.0
    assert (sample["cpu_user_percent"], sample["cpu_system_percent"]) == (30.0, 8.0)
    assert sample["cpu_iowait_percent"] == 2.0
    assert sample["network_io"][0] == {
        "iface": "eth0", "rx_bytes": 1000, "tx_bytes": 2000,
        "rx_errors": 1, "rx_dropped": 2, "tx_errors": 3, "tx_dropped": 4,
    }
    assert sample["network_io"][1] == {"iface": "veth1", "rx_bytes": 5, "tx_bytes": 6}
    links = {link["name"]: link for link in sample["network_links"]}
    assert links["eno1"]["master"] == "bond0" and links["eno1"]["speed_mbps"] == 1000
    assert links["wlp2s0"]["speed_mbps"] is None and links["wlp2s0"]["state"] == "down"
    assert links["tap100i0"]["kind"] == "virtual"
    assert sample["connectivity"] is None
    # An older agent's single CPU number still reads.
    assert parse_monitoring_output("===CPU===\n12.5\n")["cpu_user_percent"] is None
    assert parse_network_links("") == []


def test_connectivity_output_is_read() -> None:
    raw = (
        "@@GATEWAY 192.168.1.1\n"
        "@@GWPING\n"
        "3 packets transmitted, 3 received, 0% packet loss, time 402ms\n"
        "rtt min/avg/max/mdev = 0.310/0.452/0.601/0.120 ms\n"
        "@@NETPING\n"
        "3 packets transmitted, 2 received, 33.3333% packet loss, time 2003ms\n"
        "round-trip min/avg/max = 11.1/12.5/14.0 ms\n"
        "@@DNS 0 1000000000 1012500000\n"
        "@@NTPSYNC no\n"
        "@@TIMESYNC -2.5ms\n"
        "@@CHRONY 0.000123 seconds slow of NTP time\n"
    )
    reading = connectivity.parse(raw)

    assert reading["gateway"] == "192.168.1.1"
    assert (reading["gateway_latency_ms"], reading["gateway_loss_percent"]) == (0.45, 0.0)
    assert reading["internet_latency_ms"] == 12.5
    assert reading["internet_loss_percent"] == pytest.approx(33.3333)
    assert (reading["dns_ok"], reading["dns_ms"]) == (True, 12.5)
    assert reading["ntp_synced"] is False
    # chrony's offset wins over timesyncd's when both run.
    assert reading["ntp_offset_ms"] == -0.123

    lost = connectivity.parse(
        "@@GATEWAY not-an-ip\n@@NETPING\n3 packets transmitted, 0 received, "
        "100% packet loss, time 2002ms\n@@DNS 2 1 2\n@@TIMESYNC +1.5s\n"
    )
    assert lost["gateway"] is None and lost["internet_latency_ms"] is None
    assert lost["internet_loss_percent"] == 100.0
    assert (lost["dns_ok"], lost["dns_ms"]) == (False, None)
    assert lost["ntp_offset_ms"] == 1500.0
    assert connectivity.parse("") == connectivity.parse("@@NTPSYNC maybe\n")


def test_connectivity_targets_are_validated_and_quoted() -> None:
    assert connectivity.valid_target("1.1.1.1") and connectivity.valid_target("2606:4700::1111")
    assert connectivity.valid_target("debian.org") and connectivity.valid_target("nas.lan.")
    for bad in ("", "-c1", "a b", "x;rm -rf /", "$(id)", "a..b", "x" * 254):
        assert not connectivity.valid_target(bad), bad
    command = connectivity.command("1.1.1.1", "debian.org")
    assert "ping -n -q -c 3" in command and "'debian.org'" not in command
    assert "debian.org" in command
    assert "'$(id)'" in connectivity.command("1.1.1.1", "$(id)")


def test_process_list_and_detail_are_read() -> None:
    raw = (
        "@@META 100 1000.00 1001.00 4 16000000 230\n"
        "@@TOP\n4242 150\n1 3\n777 9\n"
        "@@PS\n"
        "    1     0 root          5000 Ss  86400  1 systemd\n"
        " 4242     1 www-data    204800 R      65  8 php-fpm8.2\n"
        "@@ARGS\n4242 php-fpm: pool www \n1 /sbin/init splash\n"
    )
    listing = processes.parse_list(raw, "cpu")

    assert (listing.total, listing.cores, listing.memory_total_bytes) == (230, 4, 16384000000)
    # 777 left between the snapshot and `ps`: dropped.
    assert [row.pid for row in listing.rows] == [4242, 1]
    top = listing.rows[0]
    assert top.cpu_percent == 150.0 and top.memory_bytes == 204800 * 1024
    assert top.user == "www-data" and top.name == "php-fpm8.2" and top.threads == 8
    assert top.args == "php-fpm: pool www"
    assert processes.parse_list(raw.split("@@ARGS")[0], "cpu").rows[0].args is None
    assert "/proc/$p/cmdline" not in processes.list_command("cpu", 25, include_args=False)
    assert "/proc/$p/cmdline" in processes.list_command("memory", 500, include_args=True)
    assert "head -n 100" in processes.list_command("memory", 500, include_args=True)

    stat = "4242 (php-fpm: pool (www)) R 1 4242 4242 0 -1 4194560 " + " ".join(
        ["0"] * 4
    ) + " 250 50 0 0 20 0 8 0 360000 1 2"
    detail = processes.parse_detail(
        f"@@STAT\n{stat}\n@@STATUS\nName:\tphp-fpm8.2\nState:\tR (running)\nPPid:\t1\n"
        "Uid:\t33\t33\t33\t33\nThreads:\t8\nVmRSS:\t  204800 kB\nVmSwap:\t       0 kB\n"
        "@@USER\nwww-data\n@@CGROUP\n0::/system.slice/php8.2-fpm.service\n"
        "@@CLOCK 100 4000.5 1795350000\n@@ARGS\nphp-fpm: pool www\n",
        4242,
    )
    assert detail is not None
    assert detail["name"] == "php-fpm8.2" and detail["uid"] == 33
    assert detail["start_ticks"] == 360000 and detail["started_at"] == 1795353600
    assert detail["elapsed_seconds"] == 400 and detail["cpu_seconds"] == 3.0
    assert detail["owner"] == {"kind": "service", "id": "php8.2-fpm.service"}
    assert detail["args"] == "php-fpm: pool www"
    assert processes.parse_detail("@@GONE\n", 4242) is None
    assert processes.owner_of(["0::/system.slice/docker-" + "a" * 64 + ".scope"]) == {
        "kind": "container", "id": "a" * 12
    }
    assert processes.owner_of(["0::/lxc/105/ns/init.scope"]) == {"kind": "lxc", "id": "105"}
    assert processes.owner_of(["0::/user.slice/user-0.slice/session-3.scope"]) is None


def test_signals_only_hit_the_process_shown() -> None:
    command = processes.signal_command(4242, 360000, "KILL")
    assert '[ "$S" = "360000" ]' in command and "kill -s KILL 4242" in command
    with pytest.raises(ValueError):
        processes.signal_command(1, 5, "TERM")
    with pytest.raises(ValueError):
        processes.signal_command(4242, 5, "HUP")
    assert processes.parse_signal("x\n@@OK\n") == "ok"
    assert processes.parse_signal("@@GONE") == "gone"
    assert processes.parse_signal("@@DENIED") == "denied"
    assert processes.parse_signal("") == "error"


# --- Cards ------------------------------------------------------------------------


def test_cards_from_the_newest_samples() -> None:
    machine = _machine(
        cpu_cores=8,
        network_links=[
            {"name": "eno1", "kind": "physical", "state": "up", "master": "vmbr0"},
            {"name": "eno2", "kind": "physical", "state": "down", "master": None},
            {"name": "vmbr0", "kind": "bridge", "state": "up", "master": None},
            {"name": "tap100i0", "kind": "virtual", "state": "up", "master": "vmbr0"},
        ],
        default_gateway="192.168.1.1",
    )
    machine.id = uuid.uuid4()
    older = _sample(
        machine.id, 2, cpu_percent=10.0, ram_used_bytes=1, ram_total_bytes=4,
        network_io=[
            {"iface": "eno1", "rx_bytes": 0, "tx_bytes": 0},
            {"iface": "vmbr0", "rx_bytes": 1000, "tx_bytes": 0},
            {"iface": "tap100i0", "rx_bytes": 0, "tx_bytes": 0},
        ],
        disk_io=[{"device": "sda", "read_bytes": 0, "write_bytes": 120}],
        sensor_temps=[{"name": "Package id 0", "celsius": 50}, {"name": "Core 0", "celsius": 99}],
    )
    newest = _sample(
        machine.id, 0, cpu_percent=50.0, cpu_user_percent=40.0, cpu_system_percent=8.0,
        cpu_iowait_percent=2.0, load1=1.0, load5=0.5, load15=0.25,
        ram_used_bytes=2, ram_total_bytes=4, ram_cache_bytes=1,
        network_io=[
            {"iface": "eno1", "rx_bytes": 999999, "tx_bytes": 999999},
            {"iface": "vmbr0", "rx_bytes": 1000 + 120 * 100, "tx_bytes": 120 * 50},
            {"iface": "tap100i0", "rx_bytes": 5000, "tx_bytes": 5000},
        ],
        disk_io=[{"device": "sda", "read_bytes": 1200, "write_bytes": 0}],
        filesystems=[
            {"mount": "/", "size_bytes": 100, "used_bytes": 50, "use_percent": 50},
            {"mount": "/data", "size_bytes": 100, "used_bytes": 91, "use_percent": 91},
        ],
        gateway_latency_ms=0.4, gateway_loss_percent=0.0, internet_latency_ms=12.0,
        internet_loss_percent=0.0, dns_ok=True, dns_ms=8.0, ntp_synced=True, ntp_offset_ms=0.2,
        sensor_temps=[{"name": "Package id 0", "celsius": 61}, {"name": "Core 0", "celsius": 99}],
    )

    cards = live_overview.build_cards(machine, [newest, older])

    assert cards.cpu["percent"] == 50.0 and cards.cpu["iowait"] == 2.0 and cards.cpu["cores"] == 8
    assert cards.cpu["spark"].count(",") == 2
    assert cards.memory["percent"] == 50.0 and cards.memory["cache"] == 1
    assert cards.storage["fullest"]["mount"] == "/data" and cards.storage["read"] == 10.0
    # Only the bridge counts: eno1 is its port, the tap a guest's.
    assert (cards.network["rx"], cards.network["tx"]) == (100.0, 50.0)
    assert cards.network["links"] == [
        {"kind": "physical", "up": 1, "total": 2},
        {"kind": "bridge", "up": 1, "total": 1},
        {"kind": "virtual", "up": 1, "total": 1},
    ]
    assert cards.network["internet_latency"] == 12.0 and cards.network["gateway"] == "192.168.1.1"
    # The per-core reading is a secondary sensor; the package is shown.
    assert cards.temperature is not None
    assert cards.temperature["celsius"] == 61.0 and cards.temperature["sensor"] == "Package id 0"
    assert live_overview.build_cards(machine, []).sampled_at is None
    assert live_overview.level(None, 1, 2) == "none"
    assert live_overview.level(96, 85, 95) == "critical"
    assert live_overview.sparkline([1.0]) == ""

    table = live_overview.interface_table(machine, newest, older)
    kinds = [group["kind"] for group in table]
    assert kinds == ["physical", "bridge", "virtual"]
    bridge = table[1]["links"][0]
    assert bridge["members"] == ["eno1", "tap100i0"] and bridge["rx"] == 100.0


# --- Pages -------------------------------------------------------------------------


async def _seed(db_session_factory: Any) -> uuid.UUID:
    async with db_session_factory() as db:
        machine = _machine(cpu_cores=4, docker_containers=[{"id": "a" * 64, "name": "web"}])
        db.add(machine)
        await db.flush()
        now = datetime.now(UTC)
        for minutes, cpu in ((4, 20.0), (2, 30.0), (0, 97.0)):
            db.add(
                MachineMonitoringSample(
                    machine_id=machine.id, sampled_at=now - timedelta(minutes=minutes),
                    cpu_percent=cpu, cpu_user_percent=cpu - 5, cpu_system_percent=4.0,
                    cpu_iowait_percent=1.0, ram_used_bytes=1 << 30, ram_total_bytes=4 << 30,
                    internet_latency_ms=12.0, internet_loss_percent=0.0, dns_ok=False,
                )
            )
        await db.commit()
        return machine.id


def _process(**kwargs: Any) -> dict[str, Any]:
    """A process as `processes.parse_detail` returns it."""
    return {
        "pid": 4242, "name": "php-fpm8.2", "state": "R (running)", "ppid": 1, "user": "www-data",
        "uid": 33, "threads": 8, "memory_bytes": 1024, "swap_bytes": 0, "cpu_seconds": 3.0,
        "started_at": 1795353600, "elapsed_seconds": 9, "context_switches": 5, "owner": None,
        "start_ticks": 9, "args": None, **kwargs,
    }


_LIST: dict[str, Any] = {
    "ok": True, "sort": "cpu", "total": 120, "cores": 4, "memory_total_bytes": 4 << 30,
    "processes": [
        {"pid": 4242, "cpu_percent": 88.0, "memory_bytes": 1 << 20, "memory_percent": 0.1,
         "user": "www-data", "ppid": 1, "state": "R", "elapsed_seconds": 65, "threads": 8,
         "name": "php-fpm8.2", "args": "php-fpm --secret=hunter2"},
    ],
}


async def test_overview_cards_and_top_processes(
    client: Any, db_session_factory: Any, celery_calls: Any
) -> None:
    machine_id = await _seed(db_session_factory)

    page = await client.get(f"/machines/{machine_id}")
    assert 'id="live-panel"' in page.text and 'id="processes-modal"' in page.text
    assert "live-monitoring from:body" in page.text
    panel = await client.get(f"/machines/{machine_id}/live-panel")
    assert panel.status_code == 200
    assert "97%" in panel.text and "live-critical" in panel.text
    assert f"/machines/{machine_id}/processes?sort=memory" in panel.text

    celery_calls.result_for["app.tasks.jobs.list_machine_processes"] = _LIST
    listing = await client.get(f"/machines/{machine_id}/processes?sort=bogus")
    assert listing.status_code == 200
    assert "php-fpm --secret=hunter2" in listing.text and 'hx-trigger="every 5s"' in listing.text
    assert celery_calls[-1] == (
        "app.tasks.jobs.list_machine_processes", (str(machine_id), "cpu", 25, True), {}
    )

    celery_calls.result_for["app.tasks.jobs.list_machine_processes"] = {
        "ok": False, "error": "Connection refused"
    }
    failed = await client.get(f"/machines/{machine_id}/processes")
    assert "Connection refused" in failed.text


async def test_command_lines_need_the_terminal_permission(
    client: Any, db_session_factory: Any, celery_calls: Any, login_as: Any
) -> None:
    from app.db.models.permission import Permission

    machine_id = await _seed(db_session_factory)
    await login_as(client, permissions={Permission.MACHINE_VIEW})
    celery_calls.result_for["app.tasks.jobs.list_machine_processes"] = {
        **_LIST, "processes": [{**_LIST["processes"][0], "args": None}]
    }

    listing = await client.get(f"/machines/{machine_id}/processes?sort=memory")

    assert celery_calls[-1][1] == (str(machine_id), "memory", 25, False)
    assert "php-fpm8.2" in listing.text and "hunter2" not in listing.text
    celery_calls.result_for["app.tasks.jobs.machine_process_detail"] = {
        "ok": True, "process": _process()
    }
    detail = await client.get(f"/machines/{machine_id}/processes/4242")
    assert "php-fpm8.2" in detail.text and "/signal" not in detail.text
    csrf = {"csrf_token": client.cookies.get("csrftoken")}
    denied = await client.post(
        f"/machines/{machine_id}/processes/4242/signal", data={**csrf, "start_ticks": "9"}
    )
    assert denied.status_code == 403


async def test_process_detail_and_signal(
    client: Any, db_session_factory: Any, celery_calls: Any
) -> None:
    machine_id = await _seed(db_session_factory)
    celery_calls.result_for["app.tasks.jobs.machine_process_detail"] = {
        "ok": True,
        "process": _process(
            name="nginx", user="root", start_ticks=360000, args="nginx: master",
            owner={"kind": "container", "id": "a" * 12},
        ),
    }

    detail = await client.get(f"/machines/{machine_id}/processes/4242")
    assert detail.status_code == 200
    assert "nginx: master" in detail.text and 'value="360000"' in detail.text
    assert "Docker container web" in detail.text and "hx-confirm" in detail.text
    assert (await client.get(f"/machines/{machine_id}/processes/0")).status_code == 404

    csrf = {"csrf_token": client.cookies.get("csrftoken")}
    no_csrf = await client.post(
        f"/machines/{machine_id}/processes/4242/signal", data={"start_ticks": "360000"}
    )
    assert no_csrf.status_code == 403
    bad = await client.post(
        f"/machines/{machine_id}/processes/1/signal", data={**csrf, "start_ticks": "1"}
    )
    assert bad.status_code == 400

    celery_calls.result_for["app.tasks.jobs.signal_machine_process"] = {"ok": True, "outcome": "ok"}
    sent = await client.post(
        f"/machines/{machine_id}/processes/4242/signal",
        data={**csrf, "start_ticks": "360000", "signal": "KILL", "name": "nginx"},
    )
    assert sent.status_code == 200 and "KILL" in sent.text
    assert celery_calls[-1] == (
        "app.tasks.jobs.signal_machine_process", (str(machine_id), 4242, 360000, "KILL"), {}
    )
    celery_calls.result_for["app.tasks.jobs.signal_machine_process"] = {
        "ok": False, "outcome": "gone"
    }
    gone = await client.post(
        f"/machines/{machine_id}/processes/4242/signal", data={**csrf, "start_ticks": "360000"}
    )
    assert "4242" in gone.text
    async with db_session_factory() as db:
        entries = (
            await db.execute(
                select(AuditLogEntry).where(AuditLogEntry.action == "machine.process.signal")
                .order_by(AuditLogEntry.created_at)
            )
        ).scalars().all()
    assert [e.outcome for e in entries] == [AuditOutcome.SUCCESS, AuditOutcome.FAILURE]
    assert entries[0].details["signal"] == "KILL" and entries[1].details["outcome"] == "gone"


async def test_connectivity_test(client: Any, db_session_factory: Any, celery_calls: Any) -> None:
    machine_id = await _seed(db_session_factory)
    celery_calls.result_for["app.tasks.jobs.test_machine_connectivity"] = {
        "ok": True, "internet_target": "1.1.1.1", "dns_name": "debian.org",
        "gateway": "192.168.1.1", "gateway_latency_ms": 0.5, "gateway_loss_percent": 0.0,
        "internet_latency_ms": 600.0, "internet_loss_percent": 20.0, "dns_ok": False,
        "dns_ms": None, "ntp_synced": False, "ntp_offset_ms": 1500.0,
    }
    await client.get(f"/machines/{machine_id}")
    csrf = {"csrf_token": client.cookies.get("csrftoken")}

    result = await client.post(f"/machines/{machine_id}/connectivity-test", data=csrf)

    assert result.status_code == 200
    assert "192.168.1.1" in result.text and "600.0 ms" in result.text
    assert "badge-error" in result.text and "+1500.0 ms" in result.text


# --- Settings, account units, notification fields, REST API ------------------------


async def test_connectivity_settings_are_validated(client: Any, db_session_factory: Any) -> None:
    from app.core.app_settings import get_or_create_app_settings

    await client.get("/settings?tab=checks")
    csrf = client.cookies.get("csrftoken")
    bad = await client.post(
        "/settings/checks",
        data={"csrf_token": csrf, "connectivity_internet_target": "-oProxyCommand=x"},
    )
    assert bad.status_code == 200 and "IP" in bad.text
    good = await client.post(
        "/settings/checks",
        data={
            "csrf_token": csrf, "connectivity_internet_target": " 9.9.9.9 ",
            "connectivity_dns_name": "example.org", "connectivity_checks_enabled_present": "1",
            "health_latency_warn_ms": "100", "health_latency_critical_ms": "400",
        },
    )
    assert good.status_code == 303
    async with db_session_factory() as db:
        saved = await get_or_create_app_settings(db)
        assert saved.connectivity_internet_target == "9.9.9.9"
        assert saved.connectivity_checks_enabled is False
        assert saved.health_latency_critical_ms == 400
    reversed_pair = await client.post(
        "/settings/checks",
        data={"csrf_token": csrf, "health_latency_warn_ms": "500",
              "health_latency_critical_ms": "100"},
    )
    assert reversed_pair.status_code == 200


async def test_network_units_web_and_api(client: Any, db_session_factory: Any) -> None:
    from tests.test_api_v1_extended import _api_token

    await client.get("/account")
    csrf = client.cookies.get("csrftoken")
    saved = await client.post("/account/network-units", data={"csrf_token": csrf, "units": "bits"})
    assert saved.status_code == 303
    headers = await _api_token(client)
    assert (await client.get("/api/v1/account", headers=headers)).json()["network_units"] == "bits"
    assert (
        await client.post(
            "/api/v1/account/network-units", json={"units": "parsecs"}, headers=headers
        )
    ).status_code == 422
    back = await client.post(
        "/api/v1/account/network-units", json={"units": "bytes"}, headers=headers
    )
    assert back.json() == {"network_units": "bytes"}


def test_connectivity_condition_fields() -> None:
    from app.services.condition_fields import evaluate_condition

    machine = _machine()
    sample = _sample(uuid.uuid4(), 0, internet_latency_ms=250.0, ntp_offset_ms=-1500.0)
    assert evaluate_condition("monitoring.internet_latency_ms", "gt", "200", machine, sample, None)
    assert evaluate_condition("monitoring.ntp_offset_ms", "gt", "1000", machine, sample, None)
    assert not evaluate_condition("monitoring.dns_ms", "gt", "0", machine, sample, None)


async def test_live_api(client: Any, db_session_factory: Any, celery_calls: Any) -> None:
    from tests.test_api_v1_extended import _api_token

    machine_id = await _seed(db_session_factory)
    headers = await _api_token(client)

    live = (await client.get(f"/api/v1/machines/{machine_id}/live", headers=headers)).json()
    assert live["cpu"]["percent"] == 97.0 and live["sampled_at"]
    network = (await client.get(f"/api/v1/machines/{machine_id}/network", headers=headers)).json()
    assert network["connectivity"]["internet_latency_ms"] == 12.0

    celery_calls.result_for["app.tasks.jobs.list_machine_processes"] = _LIST
    listing = await client.get(
        f"/api/v1/machines/{machine_id}/processes?sort=memory&limit=5", headers=headers
    )
    assert listing.status_code == 200 and listing.json()["processes"][0]["pid"] == 4242
    assert (
        await client.get(f"/api/v1/machines/{machine_id}/processes?sort=x", headers=headers)
    ).status_code == 422

    celery_calls.result_for["app.tasks.jobs.machine_process_detail"] = {"ok": False, "error": "x"}
    assert (
        await client.get(f"/api/v1/machines/{machine_id}/processes/4242", headers=headers)
    ).status_code == 502

    celery_calls.result_for["app.tasks.jobs.signal_machine_process"] = {"ok": True, "outcome": "ok"}
    signalled = await client.post(
        f"/api/v1/machines/{machine_id}/processes/4242/signal",
        json={"signal": "TERM", "start_ticks": 9}, headers=headers,
    )
    assert signalled.json()["outcome"] == "ok"
    assert (
        await client.post(
            f"/api/v1/machines/{machine_id}/processes/1/signal",
            json={"signal": "TERM", "start_ticks": 9}, headers=headers,
        )
    ).status_code == 400

    celery_calls.result_for["app.tasks.jobs.test_machine_connectivity"] = {
        "ok": True, "internet_target": "1.1.1.1", "internet_latency_ms": 5.0,
    }
    tested = await client.post(f"/api/v1/machines/{machine_id}/connectivity-test", headers=headers)
    assert tested.json() == {"internet_target": "1.1.1.1", "internet_latency_ms": 5.0}
    async with db_session_factory() as db:
        audited = (
            await db.execute(
                select(AuditLogEntry).where(AuditLogEntry.action == "machine.process.signal")
            )
        ).scalars().all()
    assert len(audited) == 1
