"""0.152.0: what is normal for a kind of machine (containers, bridges,
private networks — `app.services.platform_expectations`), CPU-only
temperature health, items that are gone (hidden from the charts at once,
their history deleted a day later — `app.services.vanished_series`), and
the faster monitoring history."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select

from app.db.models.machine import AuthMethod, Machine
from app.db.models.machine_monitoring_sample import MachineMonitoringSample
from app.db.models.security_audit import SecurityAudit, SecurityAuditStatus
from app.services import (
    machine_health,
    monitoring_history,
    platform_expectations,
    security_audit,
    vanished_series,
)
from app.services.machine_health import AuditSummary, Thresholds
from app.ssh import facts, monitoring

NOW = datetime(2026, 11, 28, 12, 0, tzinfo=UTC)


def _machine(**kwargs: Any) -> Machine:
    return Machine(
        name="m1",
        ip_address="192.168.1.10",
        port=22,
        username="root",
        auth_method=AuthMethod.PASSWORD,
        **kwargs,
    )


def _sample(minutes_ago: float = 0, machine_id: Any = None, **kwargs: Any) -> Any:
    return MachineMonitoringSample(
        machine_id=machine_id or uuid.uuid4(),
        sampled_at=NOW - timedelta(minutes=minutes_ago),
        **kwargs,
    )


# --- Containers -----------------------------------------------------------


def test_failed_kernel_mounts_are_normal_only_in_a_container() -> None:
    units = ["sys-kernel-config.mount", "sys-kernel-debug.mount", "nginx.service"]
    ct = _machine(virtualization="lxc")
    assert platform_expectations.filter_failed_units(ct, units) == ["nginx.service"]
    assert platform_expectations.filter_failed_units(ct, None) is None
    for kind in (None, "none", "kvm"):
        vm = _machine(virtualization=kind)
        assert platform_expectations.filter_failed_units(vm, units) == units


def test_facts_keep_the_virtualization_kind() -> None:
    parsed = facts.parse_facts_output("===VIRT===\nlxc\n")
    assert parsed["virtualization"] == "lxc" and parsed["is_physical"] is False
    assert facts.parse_facts_output("===VIRT===\nnone\n")["virtualization"] == "none"


def test_a_removed_units_lingering_failure_is_not_collected() -> None:
    assert """awk '$2 != "not-found" {print $1}'""" in monitoring.MONITORING_COMMAND


# --- Security audit -------------------------------------------------------


def _audit(machine_id: uuid.UUID) -> SecurityAudit:
    return SecurityAudit(
        machine_id=machine_id,
        status=SecurityAuditStatus.SUCCEEDED,
        warnings=[{"test": "NETW-3015", "text": "Found promiscuous interface", "detail": "vmbr0"}],
        suggestions=[
            {"test": "FIRE-4513", "text": "iptables module(s) loaded, but no rules active"},
            {"test": "SSH-7408", "text": "Consider hardening SSH configuration"},
        ],
        checks=[
            {"id": "firewall", "status": "warn"},
            {"id": "intrusion_prevention", "status": "pass"},
        ],
    )


def test_bridges_and_a_private_network_make_findings_expected() -> None:
    pve = _machine(
        id=uuid.uuid4(),
        pve_version="9.1",
        network_interfaces=[{"name": "vmbr0", "address": "192.168.1.5/24"}],
    )
    audit = _audit(pve.id)
    expected = platform_expectations.expected_audit_keys(pve, audit)
    reasons = sorted(expected.values())
    assert reasons == ["bridges", "private_network", "private_network"]
    assert security_audit.finding_key(security_audit.CHECK, {"id": "firewall"}) in expected

    view = security_audit.annotate(audit, set(), expected)
    assert {i["reason"] for i in view["expected"]} == {"bridges", "private_network"}
    assert view["counts"].suppressed == 3
    assert view["counts"].suggestions == 1  # SSH-7408 still counts
    assert view["counts"].warnings == 0

    data = security_audit.audit_to_dict(audit, suppressed=set(), expected=expected)
    assert data["active"]["warnings"] == 0 and len(data["expected"]) == 3


def test_a_public_address_keeps_firewall_findings() -> None:
    vps = _machine(
        id=uuid.uuid4(), network_interfaces=[{"name": "eth0", "address": "93.184.216.34/24"}]
    )
    assert platform_expectations.expected_audit_keys(vps, _audit(vps.id)) == {}
    # Nothing known is not "private".
    assert not platform_expectations.only_private_addresses(_machine())
    # A LAN host's global IPv6 next to a private IPv4 is still private.
    lan = _machine(
        network_interfaces=[
            {"address": "10.0.0.2/8"},
            {"address": "2001:db8::2/64"},
            {"address": "127.0.0.1/8"},
        ]
    )
    assert platform_expectations.only_private_addresses(lan)
    cgnat = _machine(network_interfaces=[{"address": "100.64.3.4/10"}])
    assert platform_expectations.only_private_addresses(cgnat)


def test_a_bridge_link_counts_without_proxmox() -> None:
    host = _machine(network_links=[{"name": "br0", "kind": "bridge"}])
    assert platform_expectations.has_bridges(host)
    assert not platform_expectations.has_bridges(_machine(network_links=[{"kind": "physical"}]))


# --- Health ---------------------------------------------------------------


def _temps(*pairs: tuple[str, float]) -> list[dict[str, Any]]:
    return [{"name": n, "celsius": c} for n, c in pairs]


def test_cpu_temperature_reads_only_the_cpu_and_gpu_has_its_own() -> None:
    samples = [
        _sample(i, sensor_temps=_temps(
            ("k10temp Tctl", 78), ("nvme Sensor 2", 87), ("i915 temp1", 99)
        ))
        for i in range(3)
    ]
    findings = machine_health.evaluate(_machine(), samples, Thresholds(), now=NOW)
    keys = {f.key: f.severity for f in findings}
    assert "cpu.temperature" not in keys
    assert keys["hardware.gpu_temperature"] == "warning"

    hot = [_sample(i, sensor_temps=_temps(("coretemp Package id 0", 98))) for i in range(3)]
    findings = machine_health.evaluate(_machine(), hot, Thresholds(), now=NOW)
    cpu = next(f for f in findings if f.key == "cpu.temperature")
    assert cpu.severity == "critical"


def test_one_hot_reading_is_averaged_away() -> None:
    samples = [
        _sample(0, sensor_temps=_temps(("k10temp Tctl", 95))),
        _sample(1, sensor_temps=_temps(("k10temp Tctl", 70))),
        _sample(2, sensor_temps=_temps(("k10temp Tctl", 70))),
    ]
    findings = machine_health.evaluate(_machine(), samples, Thresholds(), now=NOW)
    assert "cpu.temperature" not in {f.key for f in findings}


def test_lynis_warnings_alone_are_information() -> None:
    only_warnings = machine_health.evaluate(
        _machine(), [], Thresholds(), audit=AuditSummary(failed_checks=0, warnings=13), now=NOW
    )
    assert {f.key: f.severity for f in only_warnings}["security.audit"] == "info"
    failed = machine_health.evaluate(
        _machine(), [], Thresholds(), audit=AuditSummary(failed_checks=1, warnings=0), now=NOW
    )
    assert {f.key: f.severity for f in failed}["security.audit"] == "warning"


def test_an_ssh_failure_from_before_the_counter_stays_critical() -> None:
    machine = _machine(health={"findings": [], "error": "Connection refused"})
    ssh = machine_health.stored_findings(machine)[0]
    assert ssh.severity == "critical"
    machine.health = {"findings": [], "error": "Connection refused", "error_count": 1}
    assert machine_health.stored_findings(machine)[0].severity == "info"


# --- Gone items: hidden at once --------------------------------------------


def test_items_gone_from_recent_samples_are_not_charted() -> None:
    old = [
        _sample(
            60 - i,
            sensor_temps=_temps(("amdgpu edge", 50), ("k10temp Tctl", 60)),
            gpus=[{"id": "1002:699f@0000:03:00.0", "util_percent": 5}],
            docker_stats=[{"name": "old", "cpu_percent": 1}],
            network_io=[{"iface": "veth1", "rx_bytes": i, "tx_bytes": i}],
            filesystems=[{"mount": "/mnt/usb", "use_percent": 10}],
        )
        for i in range(30)
    ]
    new = [
        _sample(
            29 - i,
            sensor_temps=_temps(("i915 temp1", 45), ("k10temp Tctl", 60)),
            gpus=[{"id": "8086:56a5@0000:03:00.0", "util_percent": 3}],
            network_io=[{"iface": "eth0", "rx_bytes": i, "tx_bytes": i}],
        )
        for i in range(30)
    ]
    history = monitoring_history.build_monitoring_history(old + new, "1h")
    assert set(history.temps_by_sensor) == {"i915 temp1", "k10temp Tctl"}
    assert set(history.gpus) == {"8086:56a5@0000:03:00.0"}
    assert history.docker_cpu_by_container == {}
    assert set(history.network_rx_by_iface) == {"eth0"}
    assert history.filesystem_usage_by_mount == {}


def test_one_missed_reading_does_not_hide_a_sensor() -> None:
    samples = [_sample(3 - i, sensor_temps=_temps(("k10temp Tctl", 60))) for i in range(3)]
    samples.append(_sample(0, sensor_temps=[]))
    history = monitoring_history.build_monitoring_history(samples, "1h")
    assert "k10temp Tctl" in history.temps_by_sensor


def test_rates_are_unchanged_by_the_faster_sum() -> None:
    entries: list[dict[str, Any] | None] = [
        {"rx_bytes": 0, "tx_bytes": 0},
        {"rx_bytes": 100, "tx_bytes": 50},
        None,
        {"rx_bytes": 10, "tx_bytes": 0},  # reset
        {"rx_bytes": 20, "tx_bytes": "x"},  # junk
    ]
    stamps = [NOW + timedelta(seconds=10 * i) for i in range(5)]
    rates = monitoring_history._combined_rate_series(entries, stamps, ("rx_bytes", "tx_bytes"))
    assert rates == [None, 15.0, None, None, None]


# --- Gone items: history deleted after a day -------------------------------


def test_note_and_vanished() -> None:
    machine = _machine(monitoring_series_seen={}, docker_containers=[{"name": "stopped"}])
    sample = _sample(sensor_temps=_temps(("k10temp Tctl", 60)), gpus=[{"id": "g"}])
    vanished_series.note(machine, sample, NOW)
    stamp = int(NOW.timestamp())
    assert machine.monitoring_series_seen == {
        "sensor_temps": {"k10temp Tctl": stamp},
        "gpus": {"g": stamp},
    }
    old = int((NOW - timedelta(hours=25)).timestamp())
    seen = {
        "sensor_temps": {"amdgpu edge": old, "k10temp Tctl": stamp},
        "docker_stats": {"stopped": old, "deleted": old},
    }
    assert vanished_series.vanished(machine, seen, NOW) == {
        "sensor_temps": {"amdgpu edge": old},
        "docker_stats": {"deleted": old},
    }
    # Not built yet: left for the sweep.
    fresh = _machine()
    vanished_series.note(fresh, sample, NOW)
    assert fresh.monitoring_series_seen is None


async def test_purge_deletes_the_history_of_what_is_gone(db_session_factory: Any) -> None:
    now = datetime.now(UTC)
    async with db_session_factory() as db:
        machine = _machine()
        db.add(machine)
        await db.flush()
        for hours in (50, 30):
            db.add(MachineMonitoringSample(
                machine_id=machine.id,
                sampled_at=now - timedelta(hours=hours),
                sensor_temps=_temps(("amdgpu edge", 50), ("k10temp Tctl", 60)),
                docker_stats=[{"name": "gone", "cpu_percent": 1}],
            ))
        db.add(MachineMonitoringSample(
            machine_id=machine.id,
            sampled_at=now - timedelta(minutes=1),
            sensor_temps=_temps(("k10temp Tctl", 61)),
        ))
        await db.commit()

        # First run: no record yet, built from history, then purged.
        rewritten = await vanished_series.purge_machine(db, machine, now)
        assert rewritten == 2
        rows = (
            await db.execute(
                select(MachineMonitoringSample).order_by(MachineMonitoringSample.sampled_at)
            )
        ).scalars().all()
        for row in rows:
            await db.refresh(row)
        assert [[t["name"] for t in r.sensor_temps] for r in rows] == [
            ["k10temp Tctl"],
            ["k10temp Tctl"],
            ["k10temp Tctl"],
        ]
        assert [r.docker_stats for r in rows[:2]] == [[], []]
        seen = machine.monitoring_series_seen or {}
        assert set(seen) == {"sensor_temps"}
        assert set(seen["sensor_temps"]) == {"k10temp Tctl"}

        # Nothing left to do: nothing rewritten.
        assert await vanished_series.purge_machine(db, machine, now) == 0


async def test_the_sweep_enqueues_only_machines_with_something_gone(
    db_session_factory: Any, celery_calls: Any, monkeypatch: Any
) -> None:
    from app.tasks import jobs

    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)

    now = datetime.now(UTC)
    fresh = int(now.timestamp())
    stale = int((now - timedelta(days=2)).timestamp())
    async with db_session_factory() as db:
        quiet = _machine(monitoring_series_seen={"sensor_temps": {"a": fresh}})
        quiet.name = "quiet"
        gone = _machine(monitoring_series_seen={"sensor_temps": {"a": fresh, "b": stale}})
        gone.name = "gone"
        new = _machine()
        new.name = "new"
        db.add_all([quiet, gone, new])
        await db.commit()
        ids = {str(gone.id), str(new.id)}
    assert await jobs._purge_vanished_monitoring_series() == 2
    queued = {
        args[0]
        for name, args, _kwargs in celery_calls
        if name.endswith("purge_machine_vanished_series")
    }
    assert queued == ids


async def test_the_security_tab_lists_expected_findings_apart(
    client: Any, db_session_factory: Any
) -> None:
    async with db_session_factory() as db:
        machine = _machine(
            host_key_fingerprint="SHA256:x",
            pve_version="9.1",
            network_interfaces=[{"name": "vmbr0", "address": "192.168.1.5/24"}],
        )
        db.add(machine)
        await db.flush()
        audit = _audit(machine.id)
        audit.created_at = audit.finished_at = datetime.now(UTC)
        db.add(audit)
        await db.commit()
        machine_id = machine.id
    page = await client.get(f"/machines/{machine_id}/security")
    assert page.status_code == 200
    assert 'id="expected"' in page.text
    assert "promiscuous mode by design" in page.text
    assert "missing firewall rules are not a finding here" in page.text
