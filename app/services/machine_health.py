"""Machine health: one verdict per machine — OK, info, warning or critical —
from the readings debcontrol already collects, split into eleven categories,
each problem with a stable key so it can be snoozed on its own.

How it fits together:

- `evaluate` is pure: a machine, its newest monitoring samples, its latest
  security audit and the thresholds (Settings → Checks & retention) in, the
  problems ("findings") out. Reachability is not one of them: it changes
  every minute and is applied when the status is worked out
  (`effective_findings`).
- `refresh` runs `evaluate` and stores the result on the machine
  (`Machine.health`, `Machine.health_status`). It is called after each
  monitoring sample (taken or failed), facts refresh, update check and
  security audit; `refresh_status_only` when the reachability check sees
  the machine come or go.
  It never raises: health must not break the job that called it.
- A snoozed problem (`MachineHealthSnooze`) no longer counts until its time
  passes, someone clears it, it goes away, or it gets worse than it was.
- On a change for the worse (or back to healthy) `refresh` sends
  `machine.health_degraded` / `machine.health_recovered`. Reachability is
  left out of that (it has notifications of its own), and snoozing or
  clearing a snooze never sends one.
- `score_of` turns the statuses into one number for the Dashboard and
  the daily trend.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Iterable, Sequence
from collections.abc import Set as AbstractSet
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.app_settings import AppSettings
from app.db.models.machine import Machine
from app.db.models.machine_health_snooze import MachineHealthSnooze
from app.db.models.machine_monitoring_sample import MachineMonitoringSample
from app.db.models.notification_rule import NotificationEventType
from app.db.models.security_audit import SecurityAudit, SecurityAuditStatus
from app.i18n import DEFAULT_LOCALE_CODE, get_locale, translate
from app.ssh import proxmox

logger = logging.getLogger(__name__)

Severity = Literal["info", "warning", "critical"]
Status = Literal["ok", "info", "warning", "critical"]

SEVERITIES: tuple[Severity, ...] = ("info", "warning", "critical")
STATUSES: tuple[Status, ...] = ("ok", "info", "warning", "critical")
_RANK: dict[str, int] = {"ok": 0, "info": 1, "warning": 2, "critical": 3}

# In the order they are shown.
CATEGORIES: tuple[str, ...] = (
    "connection",
    "network",
    "cpu",
    "memory",
    "storage",
    "disks",
    "services",
    "updates",
    "security",
    "docker",
    "backups",
)

# How many of the newest samples CPU use is averaged over, so one busy
# minute does not turn a machine yellow.
CPU_SAMPLES = 3
# A clock further off than this (ms) is a warning — TLS, Kerberos, TOTP
# and log correlation start to break well before a minute.
NTP_OFFSET_WARN_MS = 1000
# Internet packet loss (percent) from which it is a warning.
PACKET_LOSS_WARN_PERCENT = 20
# A failed backup task older than this is history, not a problem now.
BACKUP_FAILURE_DAYS = 2
# A guest's newest backup older than this many days is a warning.
STALE_GUEST_BACKUP_DAYS = 7

# Snooze choices offered on the page; the API takes any number of hours.
SNOOZE_CHOICES: tuple[tuple[str, int | None], ...] = (
    ("24h", 24),
    ("7d", 24 * 7),
    ("gone", None),
)
MAX_SNOOZE_HOURS = 24 * 366


def rank(status: str | None) -> int:
    return _RANK.get(status or "", -1)


def snooze_hours_for(choice: str) -> int | None:
    for key, hours in SNOOZE_CHOICES:
        if key == choice:
            return hours
    raise ValueError(f'"{choice}" is not a snooze length.')


@dataclass(frozen=True)
class Thresholds:
    cpu_warn: int = 85
    cpu_critical: int = 95
    memory_warn: int = 85
    memory_critical: int = 95
    disk_warn: int = 85
    disk_critical: int = 95
    temperature_warn: int = 80
    temperature_critical: int = 90
    disk_full_warn_days: int = 7
    disk_full_critical_days: int = 2
    latency_warn: int = 150
    latency_critical: int = 500

    @classmethod
    def from_settings(cls, settings: AppSettings) -> Thresholds:
        return cls(
            cpu_warn=settings.health_cpu_warn_percent,
            cpu_critical=settings.health_cpu_critical_percent,
            memory_warn=settings.health_memory_warn_percent,
            memory_critical=settings.health_memory_critical_percent,
            disk_warn=settings.health_disk_warn_percent,
            disk_critical=settings.health_disk_critical_percent,
            temperature_warn=settings.health_temperature_warn_celsius,
            temperature_critical=settings.health_temperature_critical_celsius,
            disk_full_warn_days=settings.health_disk_full_warn_days,
            disk_full_critical_days=settings.health_disk_full_critical_days,
            latency_warn=settings.health_latency_warn_ms,
            latency_critical=settings.health_latency_critical_ms,
        )


@dataclass(frozen=True)
class Finding:
    """One problem. `message` is the i18n key `health.finding.<message>`,
    `params` its placeholders; `tab` is the machine tab that shows more."""

    key: str
    category: str
    severity: Severity
    message: str
    params: dict[str, Any] = field(default_factory=dict)
    tab: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "category": self.category,
            "severity": self.severity,
            "message": self.message,
            "params": dict(self.params),
            "tab": self.tab,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding | None:
        severity = data.get("severity")
        category = data.get("category")
        if severity not in SEVERITIES or category not in CATEGORIES:
            return None
        return cls(
            key=str(data.get("key") or ""),
            category=str(category),
            severity=severity,
            message=str(data.get("message") or ""),
            params=dict(data.get("params") or {}),
            tab=data.get("tab"),
        )


def _level(value: float | None, warn: int, critical: int) -> Severity | None:
    if value is None:
        return None
    if value >= critical:
        return "critical"
    if value >= warn:
        return "warning"
    return None


def _number(value: Any) -> float | None:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _cpu(samples: Sequence[MachineMonitoringSample], th: Thresholds) -> list[Finding]:
    findings: list[Finding] = []
    values = [s.cpu_percent for s in samples[:CPU_SAMPLES] if s.cpu_percent is not None]
    if values:
        average = sum(values) / len(values)
        severity = _level(average, th.cpu_warn, th.cpu_critical)
        if severity:
            findings.append(
                Finding("cpu.usage", "cpu", severity, "cpu_high",
                        {"percent": round(average)}, "monitoring")
            )
    newest = samples[0] if samples else None
    hottest: tuple[float, str] | None = None
    for sensor in (newest.sensor_temps or []) if newest else []:
        celsius = _number(sensor.get("celsius")) if isinstance(sensor, dict) else None
        if celsius is not None and (hottest is None or celsius > hottest[0]):
            hottest = (celsius, str(sensor.get("name") or ""))
    if hottest:
        severity = _level(hottest[0], th.temperature_warn, th.temperature_critical)
        if severity:
            findings.append(
                Finding("cpu.temperature", "cpu", severity, "temperature_high",
                        {"celsius": round(hottest[0]), "sensor": hottest[1]}, "monitoring")
            )
    return findings


def _network(
    machine: Machine, samples: Sequence[MachineMonitoringSample], th: Thresholds
) -> list[Finding]:
    """Connectivity seen from the machine (app.ssh.connectivity) and bond
    ports. A failure counts once it shows in the two newest samples (one
    lost round of pings is not an outage); latency is averaged like CPU."""
    findings: list[Finding] = []
    recent = list(samples[:2])

    def persistent(check: Any) -> bool:
        return bool(recent) and all(check(s) for s in recent)

    gateway_down = persistent(lambda s: (s.gateway_loss_percent or 0) >= 100)
    if gateway_down:
        findings.append(
            Finding("network.gateway", "network", "warning", "gateway_unreachable",
                    {"gateway": machine.default_gateway or "?"}, "monitoring")
        )
    if persistent(lambda s: (s.internet_loss_percent or 0) >= 100):
        if not gateway_down:
            findings.append(Finding("network.internet", "network", "warning",
                                    "internet_unreachable", {}, "monitoring"))
    else:
        newest = samples[0] if samples else None
        loss = newest.internet_loss_percent if newest else None
        if loss is not None and loss >= PACKET_LOSS_WARN_PERCENT:
            findings.append(
                Finding("network.packet_loss", "network", "warning", "internet_packet_loss",
                        {"percent": round(loss)}, "monitoring")
            )
        values = [
            s.internet_latency_ms for s in samples[:CPU_SAMPLES]
            if s.internet_latency_ms is not None
        ]
        if values:
            average = sum(values) / len(values)
            severity = _level(average, th.latency_warn, th.latency_critical)
            if severity:
                findings.append(
                    Finding("network.latency", "network", severity, "internet_latency_high",
                            {"ms": round(average)}, "monitoring")
                )
    if persistent(lambda s: s.dns_ok is False):
        findings.append(Finding("network.dns", "network", "warning", "dns_failing",
                                {}, "monitoring"))
    if persistent(lambda s: s.ntp_synced is False):
        findings.append(Finding("network.ntp", "network", "warning", "ntp_unsynced",
                                {}, "monitoring"))
    else:
        offset = samples[0].ntp_offset_ms if samples else None
        if offset is not None and abs(offset) >= NTP_OFFSET_WARN_MS:
            findings.append(
                Finding("network.ntp", "network", "warning", "ntp_offset",
                        {"ms": round(offset)}, "monitoring")
            )
    links = {str(link.get("name")): link for link in machine.network_links or []}
    for name, link in sorted(links.items()):
        master = links.get(str(link.get("master") or ""))
        if master and master.get("kind") == "bond" and link.get("state") == "down":
            findings.append(
                Finding(f"network.bond_port:{name}", "network", "warning", "bond_port_down",
                        {"name": name, "bond": master.get("name")}, "monitoring")
            )
    return findings


def _memory(newest: MachineMonitoringSample | None, th: Thresholds) -> list[Finding]:
    if newest is None or newest.ram_used_bytes is None or not newest.ram_total_bytes:
        return []
    percent = newest.ram_used_bytes / newest.ram_total_bytes * 100
    severity = _level(percent, th.memory_warn, th.memory_critical)
    if not severity:
        return []
    return [Finding("memory.usage", "memory", severity, "memory_high",
                    {"percent": round(percent)}, "monitoring")]


def _storage(
    machine: Machine, newest: MachineMonitoringSample | None, th: Thresholds
) -> list[Finding]:
    findings: list[Finding] = []
    full_mounts: set[str] = set()
    for fs in (newest.filesystems or []) if newest else []:
        mount = str(fs.get("mount") or "")
        severity = _level(_number(fs.get("use_percent")), th.disk_warn, th.disk_critical)
        if mount and severity:
            full_mounts.add(mount)
            findings.append(
                Finding(f"storage.fs:{mount}", "storage", severity, "filesystem_full",
                        {"mount": mount, "percent": fs.get("use_percent")}, "monitoring")
            )
    for mount, forecast in sorted((machine.disk_forecast or {}).items()):
        days = _number((forecast or {}).get("days_until_full"))
        if days is None or mount in full_mounts:
            continue
        filling: Severity | None = None
        if days <= th.disk_full_critical_days:
            filling = "critical"
        elif days <= th.disk_full_warn_days:
            filling = "warning"
        if filling:
            findings.append(
                Finding(f"storage.forecast:{mount}", "storage", filling, "filesystem_filling",
                        {"mount": mount, "days": round(days, 1)}, "monitoring")
            )
    for storage in machine.pve_storage or []:
        name = str(storage.get("name") or "")
        if not name or not storage.get("enabled", True):
            continue
        if not storage.get("active"):
            findings.append(
                Finding(f"storage.pve:{name}", "storage", "warning", "pve_storage_inactive",
                        {"name": name}, "proxmox")
            )
            continue
        severity = _level(_number(storage.get("used_percent")), th.disk_warn, th.disk_critical)
        if severity:
            findings.append(
                Finding(f"storage.pve:{name}", "storage", severity, "pve_storage_full",
                        {"name": name, "percent": storage.get("used_percent")}, "proxmox")
            )
    return findings


def _disks(machine: Machine, newest: MachineMonitoringSample | None) -> list[Finding]:
    findings: list[Finding] = []
    for disk in (newest.smart_disks or []) if newest else []:
        if isinstance(disk, dict) and disk.get("healthy") is False:
            device = str(disk.get("device") or "")
            findings.append(
                Finding(f"disks.smart:{device}", "disks", "critical", "smart_failed",
                        {"device": device}, "monitoring")
            )
    for pool in machine.zfs_pools or []:
        health = str(pool.get("health") or "")
        if health and health != "ONLINE":
            name = str(pool.get("name") or "")
            findings.append(
                Finding(f"disks.zfs:{name}", "disks",
                        "warning" if health == "DEGRADED" else "critical", "zfs_pool",
                        {"name": name, "health": health}, "proxmox")
            )
    return findings


def _services(machine: Machine) -> list[Finding]:
    findings = [
        Finding(f"services.unit:{unit}", "services", "warning", "unit_failed",
                {"unit": unit}, "monitoring")
        for unit in machine.failed_units or []
    ]
    cluster = machine.pve_cluster or {}
    if cluster.get("quorate") is False:
        findings.append(
            Finding("services.quorum", "services", "critical", "quorum_lost",
                    {"cluster": str(cluster.get("name") or "")}, "proxmox")
        )
    if machine.pmg_data and proxmox.mail_queue_backlog(machine.pmg_data) >= proxmox.MAIL_QUEUE_WARN:
        findings.append(
            Finding("services.mail_queue", "services", "warning", "mail_queue",
                    {"count": proxmox.mail_queue_backlog(machine.pmg_data)}, "proxmox")
        )
    return findings


def _updates(machine: Machine) -> list[Finding]:
    findings: list[Finding] = []
    if machine.security_upgradable_count:
        findings.append(
            Finding("updates.security", "updates", "warning", "security_updates",
                    {"count": machine.security_upgradable_count}, "updates")
        )
    if machine.reboot_required:
        findings.append(Finding("updates.reboot", "updates", "warning", "reboot_required",
                                {}, "updates"))
    pending = sum(
        count or 0
        for count in (
            machine.upgradable_count,
            machine.flatpak_upgradable_count,
            machine.snap_upgradable_count,
        )
    )
    if pending:
        findings.append(Finding("updates.pending", "updates", "info", "updates_pending",
                                {"count": pending}, "updates"))
    if machine.updates_check_error:
        findings.append(Finding("updates.check_error", "updates", "info", "update_check_failed",
                                {}, "updates"))
    return findings


@dataclass(frozen=True)
class AuditSummary:
    """The open findings of a machine's latest successful security audit."""

    failed_checks: int
    warnings: int


def _security(machine: Machine, audit: AuditSummary | None) -> list[Finding]:
    findings: list[Finding] = []
    if audit and (audit.failed_checks or audit.warnings):
        findings.append(
            Finding("security.audit", "security", "warning", "audit_findings",
                    {"failed": audit.failed_checks, "warnings": audit.warnings}, "security")
        )
    return findings


def _docker(machine: Machine) -> list[Finding]:
    findings: list[Finding] = []
    if machine.docker_status == "no_access":
        findings.append(Finding("docker.no_access", "docker", "info", "docker_no_access",
                                {}, "docker"))
    if machine.docker_status == "ok":
        for container in machine.docker_containers or []:
            name = str(container.get("name") or "")
            if container.get("health") == "unhealthy":
                findings.append(
                    Finding(f"docker.container:{name}", "docker", "warning",
                            "container_unhealthy", {"name": name}, "docker")
                )
            elif container.get("state") == "restarting":
                findings.append(
                    Finding(f"docker.container:{name}", "docker", "warning",
                            "container_restarting", {"name": name}, "docker")
                )
    vulns = machine.docker_vulnerabilities or {}
    critical, high = int(vulns.get("critical") or 0), int(vulns.get("high") or 0)
    if critical or high:
        findings.append(
            Finding("docker.vulnerabilities", "docker", "warning" if critical else "info",
                    "image_vulnerabilities", {"critical": critical, "high": high}, "docker")
        )
    return findings


def _backups(machine: Machine, now: datetime) -> list[Finding]:
    findings: list[Finding] = []
    uncovered, _signed_off = proxmox.split_not_backed_up(
        machine.pve_backups, machine.pve_backup_exempt, machine.pve_guests
    )
    if uncovered:
        findings.append(
            Finding("backups.not_backed_up", "backups", "warning", "guests_not_backed_up",
                    {"count": len(uncovered)}, "proxmox")
        )
    cutoff = int((now - timedelta(days=BACKUP_FAILURE_DAYS)).timestamp())
    last = proxmox.last_backup(machine.pve_backups)
    if last and last.get("ok") is False and int(last.get("started_at") or 0) >= cutoff:
        findings.append(Finding("backups.failed", "backups", "warning", "backup_failed",
                                {}, "proxmox"))
    oldest = proxmox.oldest_guest_backup_days(
        machine.pve_guests, machine.pve_guest_backups, machine.pve_backup_exempt,
        int(now.timestamp()),
    )
    if oldest is not None and oldest > STALE_GUEST_BACKUP_DAYS:
        findings.append(Finding("backups.stale", "backups", "warning", "guest_backup_stale",
                                {"days": oldest}, "proxmox"))
    pbs = proxmox.pbs_failures(machine.pbs_data)
    if pbs:
        findings.append(Finding("backups.pbs", "backups", "warning", "pbs_failures",
                                {"count": len(pbs)}, "proxmox"))
    return findings


def evaluate(
    machine: Machine,
    samples: Sequence[MachineMonitoringSample],
    thresholds: Thresholds,
    *,
    audit: AuditSummary | None = None,
    now: datetime | None = None,
) -> list[Finding]:
    """Every problem on `machine` right now, reachability aside. `samples`
    are its newest monitoring samples, newest first."""
    now = now or datetime.now(UTC)
    newest = samples[0] if samples else None
    findings: list[Finding] = []
    if machine.host_key_changed_fingerprint:
        findings.append(Finding("connection.host_key", "connection", "critical",
                                "host_key_changed", {}, None))
    findings += _network(machine, samples, thresholds)
    findings += _cpu(samples, thresholds)
    findings += _memory(newest, thresholds)
    findings += _storage(machine, newest, thresholds)
    findings += _disks(machine, newest)
    findings += _services(machine)
    findings += _updates(machine)
    findings += _security(machine, audit)
    findings += _docker(machine)
    findings += _backups(machine, now)
    return findings


# --- Reading what is stored -------------------------------------------------


def stored_findings(machine: Machine) -> list[Finding]:
    record = machine.health or {}
    findings = [Finding.from_dict(f) for f in record.get("findings") or [] if isinstance(f, dict)]
    result = [f for f in findings if f is not None]
    error = record.get("error")
    if error:
        result.insert(0, Finding("connection.ssh", "connection", "critical", "ssh_failed",
                                 {"error": str(error)[:300]}, None))
    return result


def effective_findings(machine: Machine) -> list[Finding]:
    """The stored findings plus reachability: an unreachable machine is
    critical, and its SSH error (which follows from it) is left out."""
    findings = stored_findings(machine)
    if machine.is_reachable is False:
        findings = [f for f in findings if f.key != "connection.ssh"]
        findings.insert(0, Finding("connection.unreachable", "connection", "critical",
                                   "unreachable", {}, None))
    return findings


def snooze_active(
    snooze: MachineHealthSnooze, finding: Finding | None, now: datetime
) -> bool:
    """Still in force for `finding` (its current state)."""
    if snooze.until is not None:
        until = snooze.until if snooze.until.tzinfo else snooze.until.replace(tzinfo=UTC)
        if until <= now:
            return False
    return not (finding is not None and rank(finding.severity) > rank(snooze.severity))


@dataclass
class HealthView:
    """A machine's health as shown: the status, what counts, what is
    snoozed (with its snooze), and what each category says."""

    status: Status | None
    active: list[Finding]
    snoozed: list[tuple[Finding, MachineHealthSnooze]]
    evaluated_at: datetime | None

    def category_status(self, category: str) -> Status:
        worst: Status = "ok"
        for finding in self.active:
            if finding.category == category and rank(finding.severity) > rank(worst):
                worst = finding.severity
        return worst

    @property
    def categories(self) -> list[tuple[str, Status, list[Finding], list[Finding]]]:
        return [
            (
                category,
                self.category_status(category),
                [f for f in self.active if f.category == category],
                [f for f, _s in self.snoozed if f.category == category],
            )
            for category in CATEGORIES
        ]

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "evaluated_at": self.evaluated_at.isoformat() if self.evaluated_at else None,
            "categories": {c: self.category_status(c) for c in CATEGORIES},
            "problems": [f.as_dict() for f in self.active],
            "snoozed": [
                {**f.as_dict(), "snooze": snooze_to_dict(s)} for f, s in self.snoozed
            ],
        }


def _evaluated_at(machine: Machine) -> datetime | None:
    raw = (machine.health or {}).get("at")
    try:
        return datetime.fromisoformat(raw) if isinstance(raw, str) else None
    except ValueError:
        return None


def build_view(
    machine: Machine, snoozes: Iterable[MachineHealthSnooze], now: datetime | None = None
) -> HealthView:
    now = now or datetime.now(UTC)
    by_key = {s.finding_key: s for s in snoozes}
    active: list[Finding] = []
    snoozed: list[tuple[Finding, MachineHealthSnooze]] = []
    findings = effective_findings(machine)
    for finding in findings:
        snooze = by_key.get(finding.key)
        if snooze is not None and snooze_active(snooze, finding, now):
            snoozed.append((finding, snooze))
        else:
            active.append(finding)
    status: Status | None
    if machine.health is None and machine.is_reachable is not False:
        status = None
    else:
        status = "ok"
        for finding in active:
            if rank(finding.severity) > rank(status):
                status = finding.severity
    order = {c: i for i, c in enumerate(CATEGORIES)}
    active.sort(key=lambda f: (-rank(f.severity), order.get(f.category, 99), f.key))
    return HealthView(status=status, active=active, snoozed=snoozed,
                      evaluated_at=_evaluated_at(machine))


async def snoozes_for(db: AsyncSession, machine_id: uuid.UUID) -> list[MachineHealthSnooze]:
    result = await db.execute(
        select(MachineHealthSnooze)
        .where(MachineHealthSnooze.machine_id == machine_id)
        .order_by(MachineHealthSnooze.created_at)
    )
    return list(result.scalars().all())


async def view_for(db: AsyncSession, machine: Machine) -> HealthView:
    return build_view(machine, await snoozes_for(db, machine.id))


def snooze_to_dict(snooze: MachineHealthSnooze) -> dict[str, Any]:
    return {
        "id": str(snooze.id),
        "machine_id": str(snooze.machine_id),
        "finding_key": snooze.finding_key,
        "severity": snooze.severity,
        "until": snooze.until.isoformat() if snooze.until else None,
        "note": snooze.note,
        "created_by": snooze.created_by,
        "created_at": snooze.created_at.isoformat() if snooze.created_at else None,
    }


# --- Text -------------------------------------------------------------------


def finding_text(finding: Finding, locale_code: str | None = None) -> str:
    """The finding as one sentence, in `locale_code` (English by default)."""
    locale = get_locale(locale_code or DEFAULT_LOCALE_CODE)
    return translate(locale, f"health.finding.{finding.message}", **finding.params)


# --- Evaluating and storing -------------------------------------------------


async def _newest_samples(db: AsyncSession, machine_id: uuid.UUID) -> list[MachineMonitoringSample]:
    result = await db.execute(
        select(MachineMonitoringSample)
        .where(MachineMonitoringSample.machine_id == machine_id)
        .order_by(MachineMonitoringSample.sampled_at.desc())
        .limit(CPU_SAMPLES)
    )
    return list(result.scalars().all())


async def _audit_summary(db: AsyncSession, machine_id: uuid.UUID) -> AuditSummary | None:
    # Imported here: security_audit imports the SSH layer, which this
    # module (read by templates) does not otherwise need.
    from app.services import security_audit

    audit = await db.scalar(
        select(SecurityAudit)
        .where(
            SecurityAudit.machine_id == machine_id,
            SecurityAudit.status == SecurityAuditStatus.SUCCEEDED,
        )
        .order_by(SecurityAudit.created_at.desc())
        .limit(1)
    )
    if audit is None:
        return None
    suppressed = set(await security_audit.suppressions(db, machine_id))
    counts = security_audit.counts(audit, suppressed)
    return AuditSummary(failed_checks=counts.failed_checks, warnings=counts.warnings)


async def apply_status(db: AsyncSession, machine: Machine) -> HealthView:
    """Recompute `Machine.health_status` from what is stored, the snoozes
    and reachability, dropping snoozes whose problem has gone or whose time
    has passed. The caller commits."""
    now = datetime.now(UTC)
    snoozes = await snoozes_for(db, machine.id)
    if machine.health is not None:
        present = {f.key for f in effective_findings(machine)}
        stale = [
            s.id
            for s in snoozes
            if s.finding_key not in present
            or (s.until is not None and not snooze_active(s, None, now))
        ]
        if stale:
            await db.execute(delete(MachineHealthSnooze).where(MachineHealthSnooze.id.in_(stale)))
            snoozes = [s for s in snoozes if s.id not in stale]
    view = build_view(machine, snoozes, now)
    machine.health_status = view.status
    return view


async def refresh(
    db: AsyncSession,
    machine: Machine,
    *,
    error: str | None = None,
    notify_changes: bool = True,
) -> None:
    """Evaluate `machine` and store the result, then notify on a change of
    status. `error`: the sample could not be taken (SSH failed) — the
    previous findings are kept and the error is added. Commits; never
    raises."""
    try:
        # The calling job may have rolled back (expiring the machine) or
        # another job may have written since: start from what is stored.
        await db.refresh(machine)
        previous = _notified(machine)
        status_before = machine.health_status
        now = datetime.now(UTC)
        if error is not None:
            record = dict(machine.health or {"findings": []})
            record["error"] = error[:500]
            record.setdefault("at", now.isoformat())
            machine.health = record
        else:
            from app.core.app_settings import get_or_create_app_settings

            settings = await get_or_create_app_settings(db)
            findings = evaluate(
                machine,
                await _newest_samples(db, machine.id),
                Thresholds.from_settings(settings),
                audit=await _audit_summary(db, machine.id),
                now=now,
            )
            machine.health = {
                "at": now.isoformat(),
                "findings": [f.as_dict() for f in findings],
                "error": None,
            }
        view = await apply_status(db, machine)
        current = _basis(view)
        _remember_notified(machine, current)
        await db.commit()
        # The open pages redraw on a change (the first evaluation shows up
        # with their next poll).
        if status_before is not None and machine.health_status != status_before:
            await _publish_status(machine)
        if notify_changes:
            await _notify_change(db, machine, previous, current, view)
    except Exception:
        logger.warning("Health evaluation failed for %s", machine.name, exc_info=True)
        await db.rollback()


async def _publish_status(machine: Machine) -> None:
    from app.services.live_updates import KIND_STATUS, publish_fleet_event, publish_machine_event

    await publish_machine_event(str(machine.id), KIND_STATUS)
    await publish_fleet_event(KIND_STATUS)


def _basis(view: HealthView) -> str | None:
    """The status notifications go by: reachability left out, since being
    unreachable (and back) has notifications of its own."""
    if view.status is None:
        return None
    worst: Status = "ok"
    for finding in view.active:
        if finding.key != "connection.unreachable" and rank(finding.severity) > rank(worst):
            worst = finding.severity
    return worst


def _notified(machine: Machine) -> str | None:
    value = (machine.health or {}).get("notified")
    return value if isinstance(value, str) and value in STATUSES else None


def _remember_notified(machine: Machine, status: str | None) -> None:
    if machine.health is not None and machine.health.get("notified") != status:
        machine.health = {**machine.health, "notified": status}


def degraded(previous: str | None, current: str | None) -> bool:
    """Worse than before, and at least a warning. Never from unknown: the
    first evaluation (after an upgrade) does not page anyone about problems
    that were already there."""
    return previous is not None and rank(current) >= rank("warning") and rank(current) > rank(
        previous
    )


def recovered(previous: str | None, current: str | None) -> bool:
    return rank(previous) >= rank("warning") and current in ("ok", "info")


async def _notify_change(
    db: AsyncSession,
    machine: Machine,
    previous: str | None,
    current: str | None,
    view: HealthView,
) -> None:
    from app.services.notifications import notify

    if degraded(previous, current):
        event = NotificationEventType.HEALTH_DEGRADED
    elif recovered(previous, current):
        event = NotificationEventType.HEALTH_RECOVERED
    else:
        return
    problems = [
        f for f in view.active if f.severity != "info" and f.key != "connection.unreachable"
    ]
    await notify(
        db,
        event,
        machine=machine,
        context={
            "status": current or "",
            "previous_status": previous or "",
            "problem_count": len(problems),
            "problems": "\n".join(f"- {finding_text(f)}" for f in problems) or "-",
        },
    )


async def refresh_status_only(db: AsyncSession, machine: Machine) -> None:
    """After reachability changed: recompute the status from what is
    stored. Sends nothing — reachability has its own notifications, and the
    caller rings the live-update doorbell. Commits; never raises."""
    try:
        await apply_status(db, machine)
        await db.commit()
    except Exception:
        logger.warning("Health status update failed for %s", machine.name, exc_info=True)
        await db.rollback()


# --- Snoozing ---------------------------------------------------------------


class UnknownFindingError(LookupError):
    """No current problem with that key on the machine."""


async def snooze(
    db: AsyncSession,
    machine: Machine,
    key: str,
    *,
    hours: int | None,
    by: str | None,
    note: str | None = None,
) -> MachineHealthSnooze:
    """Snooze the current problem `key` for `hours` (None = until it is
    gone). Replaces an earlier snooze of the same problem. The caller
    commits."""
    finding = next((f for f in effective_findings(machine) if f.key == key), None)
    if finding is None:
        raise UnknownFindingError(key)
    if key == "connection.unreachable":
        # That is what acknowledging the machine is for.
        raise ValueError("Being unreachable cannot be snoozed; acknowledge the machine instead.")
    if hours is not None and not 1 <= hours <= MAX_SNOOZE_HOURS:
        raise ValueError(f"hours must be between 1 and {MAX_SNOOZE_HOURS}")
    await db.execute(
        delete(MachineHealthSnooze).where(
            MachineHealthSnooze.machine_id == machine.id, MachineHealthSnooze.finding_key == key
        )
    )
    row = MachineHealthSnooze(
        machine_id=machine.id,
        finding_key=key,
        severity=finding.severity,
        until=datetime.now(UTC) + timedelta(hours=hours) if hours is not None else None,
        note=(note or "").strip()[:500] or None,
        created_by=by,
        created_at=datetime.now(UTC),
    )
    db.add(row)
    await db.flush()
    # Silently: snoozing the last problem is not "healthy again".
    _remember_notified(machine, _basis(await apply_status(db, machine)))
    return row


async def unsnooze(db: AsyncSession, machine: Machine, key: str) -> bool:
    """End the snooze of `key`. False when there was none. The caller
    commits."""
    result = await db.execute(
        delete(MachineHealthSnooze).where(
            MachineHealthSnooze.machine_id == machine.id, MachineHealthSnooze.finding_key == key
        )
    )
    _remember_notified(machine, _basis(await apply_status(db, machine)))
    return bool(getattr(result, "rowcount", 0))


# --- The fleet --------------------------------------------------------------


@dataclass
class FleetHealth:
    counts: dict[str, int]
    unknown: int
    score: int | None

    def as_dict(self) -> dict[str, Any]:
        return {"counts": dict(self.counts), "unknown": self.unknown, "score": self.score}


def score_of(counts: dict[str, int]) -> int | None:
    """0-100: a healthy (or only informational) machine counts fully, one
    with a warning half, a critical one not at all. None with no machine
    evaluated."""
    known = sum(counts.get(s, 0) for s in STATUSES)
    if not known:
        return None
    points = counts.get("ok", 0) + counts.get("info", 0) + counts.get("warning", 0) * 0.5
    return round(points / known * 100)


async def fleet_health(
    db: AsyncSession, group_ids: AbstractSet[uuid.UUID] | None = None
) -> FleetHealth:
    """Counts per status over active machines (`group_ids`: the groups a
    restricted account may see, or None for the whole fleet)."""
    query = select(Machine.health_status, func.count()).where(Machine.is_active)
    if group_ids is not None:
        query = query.where(Machine.group_id.in_(group_ids))
    rows = (await db.execute(query.group_by(Machine.health_status))).all()
    counts: dict[str, int] = dict.fromkeys(STATUSES, 0)
    unknown = 0
    for status, count in rows:
        if status in counts:
            counts[status] = count
        else:
            unknown += count
    return FleetHealth(counts=counts, unknown=unknown, score=score_of(counts))


async def worst_machines(
    db: AsyncSession, group_ids: AbstractSet[uuid.UUID] | None = None, limit: int = 5
) -> list[tuple[Machine, HealthView]]:
    """The machines with a warning or a critical problem, worst first
    (`limit` 0 = all of them)."""
    query = select(Machine).where(
        Machine.is_active, Machine.health_status.in_(("warning", "critical"))
    )
    if group_ids is not None:
        query = query.where(Machine.group_id.in_(group_ids))
    machines = list((await db.execute(query)).scalars().all())
    if not machines:
        return []
    snooze_rows = (
        await db.execute(
            select(MachineHealthSnooze).where(
                MachineHealthSnooze.machine_id.in_([m.id for m in machines])
            )
        )
    ).scalars().all()
    by_machine: dict[uuid.UUID, list[MachineHealthSnooze]] = {}
    for row in snooze_rows:
        by_machine.setdefault(row.machine_id, []).append(row)
    views = [(m, build_view(m, by_machine.get(m.id, []))) for m in machines]
    views.sort(
        key=lambda mv: (
            -rank(mv[1].status),
            -sum(1 for f in mv[1].active if f.severity != "info"),
            mv[0].name.lower(),
        )
    )
    return views[:limit] if limit else views


async def all_snoozes(
    db: AsyncSession, group_ids: AbstractSet[uuid.UUID] | None = None
) -> list[tuple[Machine, MachineHealthSnooze, Finding | None]]:
    """Every snooze in force across the (visible) fleet, newest first, with
    the problem it is for."""
    query = select(MachineHealthSnooze, Machine).join(
        Machine, Machine.id == MachineHealthSnooze.machine_id
    )
    if group_ids is not None:
        query = query.where(Machine.group_id.in_(group_ids))
    rows = (await db.execute(query.order_by(MachineHealthSnooze.created_at.desc()))).all()
    now = datetime.now(UTC)
    result: list[tuple[Machine, MachineHealthSnooze, Finding | None]] = []
    for snooze_row, machine in rows:
        finding = next(
            (f for f in effective_findings(machine) if f.key == snooze_row.finding_key), None
        )
        if snooze_row.until is not None and not snooze_active(snooze_row, None, now):
            continue
        result.append((machine, snooze_row, finding))
    return result
