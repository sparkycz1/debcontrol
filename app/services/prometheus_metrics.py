"""The fleet's current state as Prometheus metrics (text exposition format
0.0.4) — `GET /api/v1/metrics`. Everything comes from what is already
stored (each machine's row, its newest monitoring sample, each endpoint
check's last result); scraping opens no SSH connection and costs three
queries whatever the fleet size.

Label values are escaped the way the format requires. Machine names are
labels, so a scrape shows exactly the machines its token's account may
see and nothing about the others.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from app.core.version import APP_VERSION
from app.db.models.endpoint_check import EndpointCheck
from app.db.models.machine import Machine
from app.services.fleet_overview import FleetRow

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"

_Value = float | int | bool


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _number(value: _Value) -> str:
    if isinstance(value, bool):
        return "1" if value else "0"
    return repr(value) if isinstance(value, float) else str(value)


@dataclass
class _Metric:
    name: str
    help: str
    samples: list[tuple[dict[str, str], _Value]] = field(default_factory=list)

    def add(self, labels: dict[str, str], value: _Value | None) -> None:
        if value is not None:
            self.samples.append((labels, value))

    def render(self) -> Iterable[str]:
        if not self.samples:
            return
        yield f"# HELP {self.name} {self.help}"
        yield f"# TYPE {self.name} gauge"
        for labels, value in self.samples:
            text = ",".join(f'{key}="{_escape(val)}"' for key, val in labels.items())
            yield f"{self.name}{{{text}}} {_number(value)}" if text else (
                f"{self.name} {_number(value)}"
            )


def _machine_metrics(machines: list[Machine], rows: list[FleetRow]) -> list[_Metric]:
    up = _Metric("debcontrol_machine_up", "1 if the machine answered its last SSH check.")
    updates = _Metric("debcontrol_machine_pending_updates", "Pending apt updates.")
    security = _Metric(
        "debcontrol_machine_pending_security_updates", "Pending apt security updates."
    )
    reboot = _Metric("debcontrol_machine_reboot_required", "1 if the machine needs a reboot.")
    failed = _Metric("debcontrol_machine_failed_units", "systemd units in the failed state.")
    cpu = _Metric("debcontrol_machine_cpu_percent", "CPU use in the newest monitoring sample.")
    ram = _Metric("debcontrol_machine_memory_percent", "RAM use in the newest sample.")
    load = _Metric("debcontrol_machine_load1", "1-minute load average in the newest sample.")
    disk = _Metric(
        "debcontrol_machine_disk_percent", "Use of the fullest filesystem in the newest sample."
    )
    temperature = _Metric(
        "debcontrol_machine_temperature_celsius", "Hottest sensor in the newest sample."
    )
    uptime = _Metric("debcontrol_machine_uptime_seconds", "Uptime at the last facts refresh.")
    sampled = _Metric(
        "debcontrol_machine_sample_timestamp_seconds",
        "When the newest monitoring sample was taken (Unix time).",
    )
    for machine, row in zip(machines, rows, strict=True):
        labels = {"machine": machine.name, "group": machine.group.name if machine.group else ""}
        up.add(labels, machine.is_reachable)
        updates.add(labels, machine.upgradable_count)
        security.add(labels, machine.security_upgradable_count)
        reboot.add(labels, machine.reboot_required)
        failed.add(labels, len(machine.failed_units) if machine.failed_units is not None else None)
        cpu.add(labels, row.cpu_percent)
        ram.add(labels, round(row.ram_percent, 2) if row.ram_percent is not None else None)
        load.add(labels, row.load1)
        if row.disk_percent is not None:
            disk.add({**labels, "mount": row.disk_mount or ""}, row.disk_percent)
        temperature.add(labels, row.temperature_c)
        uptime.add(labels, row.uptime_seconds)
        sampled.add(labels, int(row.sampled_at.timestamp()) if row.sampled_at else None)
    return [
        up, updates, security, reboot, failed, cpu, ram, load, disk, temperature, uptime, sampled
    ]


def _check_metrics(checks: list[EndpointCheck]) -> list[_Metric]:
    check_up = _Metric("debcontrol_check_up", "1 if the endpoint check passed last time.")
    latency = _Metric(
        "debcontrol_check_latency_seconds", "How long the endpoint check's last probe took."
    )
    certificate = _Metric(
        "debcontrol_check_certificate_expiry_timestamp_seconds",
        "When the checked endpoint's TLS certificate expires (Unix time).",
    )
    for check in checks:
        if not check.enabled:
            continue
        labels = {"check": check.name, "kind": check.kind}
        check_up.add(labels, check.last_ok)
        latency.add(
            labels,
            round(check.last_latency_ms / 1000, 4) if check.last_latency_ms is not None else None,
        )
        certificate.add(
            labels, int(check.cert_expires_at.timestamp()) if check.cert_expires_at else None
        )
    return [check_up, latency, certificate]


def render(machines: list[Machine], rows: list[FleetRow], checks: list[EndpointCheck]) -> str:
    """`rows[i]` is the overview row of `machines[i]`."""
    info = _Metric("debcontrol_info", "The debcontrol instance answering this scrape.")
    info.add({"version": APP_VERSION}, 1)
    total = _Metric("debcontrol_machines", "Machines this token's account can see.")
    total.add({}, len(machines))

    lines: list[str] = []
    for metric in [info, total, *_machine_metrics(machines, rows), *_check_metrics(checks)]:
        lines.extend(metric.render())
    return "\n".join(lines) + "\n"
