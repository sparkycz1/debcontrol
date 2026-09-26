"""Configuration drift: what changed on a machine since the previous facts
refresh or update check — recorded as `MachineChange` rows (the History
tab) and announced through the `machine.config_changed` /
`machine.security_updates` notification events.

- **Facts** (`record_fact_changes`, from `app.tasks.jobs._refresh_machine_facts`):
  a snapshot of `TRACKED_FIELDS` is taken before the new facts are applied
  and compared with the one after. A value that was unknown before
  (never refreshed, or a fact this version started collecting) or is
  unknown now (the command couldn't tell) is not a change — so the first
  refresh after an upgrade stays quiet.
- **Security updates** (`record_new_security_updates`, from
  `app.tasks.jobs._check_machine_updates`): apt security updates pending
  now that weren't pending at the previous check. The first check after an
  upgrade, with a stored list that predates the per-package `security`
  flag, only sets the baseline.

Pure diffing (`snapshot`, `diff_snapshots`, `new_security_packages`) is
kept separate from the database/notification side so it can be tested
without either.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.machine import Machine
from app.db.models.machine_change import MachineChange
from app.db.models.notification_rule import NotificationEventType
from app.services.notifications import notify
from app.ssh.security_advisories import cve_sort_key

# field -> (label, is_set). A set-valued field records what was removed
# (`old_value`) and added (`new_value`); a scalar one the before/after.
TRACKED_FIELDS: dict[str, tuple[str, bool]] = {
    "hostname": ("Hostname", False),
    "os_version": ("Operating system", False),
    "kernel_version": ("Kernel", False),
    "cpu_cores": ("CPU cores", False),
    "ram": ("RAM", False),
    "disks": ("Disks", True),
    "filesystems": ("Mounted filesystems", True),
    "ip_addresses": ("IP addresses", True),
    "listening_ports": ("Listening TCP ports", True),
    "admin_users": ("Admin accounts", True),
    "login_users": ("Login accounts", True),
}

SECURITY_FIELD = "security_updates"
# More items than this in one change are summarized as "... and N more".
_MAX_LISTED = 30

Snapshot = dict[str, str | frozenset[str] | None]


@dataclass(frozen=True)
class FieldChange:
    field: str
    old_value: str | None
    new_value: str | None

    @property
    def label(self) -> str:
        return TRACKED_FIELDS.get(self.field, (self.field, False))[0]

    @property
    def is_set(self) -> bool:
        return TRACKED_FIELDS.get(self.field, (self.field, False))[1]

    def describe(self) -> str:
        """One line for a notification: `Kernel: 6.1.0-25 → 6.1.0-26`,
        `Listening TCP ports: +0.0.0.0:8080 -0.0.0.0:21`."""
        if self.is_set:
            parts = []
            if self.new_value:
                parts.append("+" + self.new_value)
            if self.old_value:
                parts.append("-" + self.old_value)
            return f"{self.label}: {' '.join(parts)}"
        return f"{self.label}: {self.old_value or '—'} → {self.new_value or '—'}"


def _gib(value: int | None) -> str | None:
    # Rounded to whole GiB: MemTotal moves by a few MB between kernels,
    # which is not a hardware change.
    return None if value is None else f"{round(value / 1024**3)} GiB"


def _names(items: Iterable[Any] | None, key: Any) -> frozenset[str] | None:
    if items is None:
        return None
    values: set[str] = set()
    for item in items:
        value = key(item)
        if value:
            values.add(str(value))
    return frozenset(values)


def snapshot(machine: Machine) -> Snapshot:
    """The tracked facts of `machine` as comparable values."""
    return {
        "hostname": machine.discovered_hostname,
        "os_version": machine.os_version,
        "kernel_version": machine.kernel_version,
        "cpu_cores": None if machine.cpu_cores is None else str(machine.cpu_cores),
        "ram": _gib(machine.ram_bytes),
        "disks": _names(
            machine.disks,
            lambda d: (
                f"{d.get('name')} ({round((d.get('size_bytes') or 0) / 1000**3)} GB)"
                if isinstance(d, dict)
                else None
            ),
        ),
        "filesystems": _names(
            machine.filesystems, lambda f: f.get("mount") if isinstance(f, dict) else None
        ),
        "ip_addresses": _names(
            machine.network_interfaces,
            lambda n: (
                f"{n.get('interface')} {n.get('address')}" if isinstance(n, dict) else None
            ),
        ),
        "listening_ports": _names(machine.listening_ports, str),
        "admin_users": _names(machine.admin_users, str),
        "login_users": _names(machine.login_users, str),
    }


def _join(values: Iterable[str]) -> str | None:
    ordered = sorted(values)
    if not ordered:
        return None
    shown = ", ".join(ordered[:_MAX_LISTED])
    if len(ordered) > _MAX_LISTED:
        shown += f", … (+{len(ordered) - _MAX_LISTED})"
    return shown


def diff_snapshots(before: Snapshot, after: Snapshot) -> list[FieldChange]:
    changes: list[FieldChange] = []
    for field, (_label, is_set) in TRACKED_FIELDS.items():
        old, new = before.get(field), after.get(field)
        if old is None or new is None or old == new:
            continue
        if is_set and isinstance(old, frozenset) and isinstance(new, frozenset):
            changes.append(FieldChange(field, _join(old - new), _join(new - old)))
        elif not is_set:
            changes.append(FieldChange(field, str(old), str(new)))
    return changes


def _describe_package(package: dict[str, Any]) -> str:
    text = f"{package.get('name')} {package.get('new_version') or ''}".strip()
    cves = package.get("cves")
    if isinstance(cves, list) and cves:
        shown = ", ".join(str(c) for c in cves[:5])
        text += f" ({shown}{', …' if len(cves) > 5 else ''})"
    return text


def new_security_packages(
    previous: list[dict[str, Any]] | None, current: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Security packages in `current` whose (name, new version) wasn't
    pending in `previous`. Empty when `previous` can't serve as a baseline:
    never checked (None), or stored before the `security` flag existed."""
    if previous is None or any(
        isinstance(p, dict) and "security" not in p for p in previous
    ):
        return []
    before = {
        (p.get("name"), p.get("new_version"))
        for p in previous
        if isinstance(p, dict) and p.get("security")
    }
    return [
        p
        for p in current
        if p.get("security") and (p.get("name"), p.get("new_version")) not in before
    ]


async def record_fact_changes(
    db: AsyncSession, machine: Machine, changes: list[FieldChange], now: datetime | None = None
) -> None:
    """Store `changes`, commit, and notify. No-op for an empty list."""
    if not changes:
        return
    detected_at = now or datetime.now(UTC)
    db.add_all(
        MachineChange(
            machine_id=machine.id,
            detected_at=detected_at,
            category="facts",
            field=change.field,
            old_value=change.old_value,
            new_value=change.new_value,
        )
        for change in changes
    )
    await db.commit()
    summary = "\n".join(change.describe() for change in changes)
    await notify(
        db,
        NotificationEventType.MACHINE_CONFIG_CHANGED,
        machine=machine,
        context={"changes": summary, "details": summary},
    )


async def record_new_security_updates(
    db: AsyncSession,
    machine: Machine,
    packages: list[dict[str, Any]],
    now: datetime | None = None,
) -> None:
    """Store one change row for newly pending security updates, commit,
    and notify. No-op for an empty list."""
    if not packages:
        return
    described = [_describe_package(p) for p in packages]
    cves = sorted(
        {str(c) for p in packages for c in (p.get("cves") or []) if isinstance(c, str)},
        key=cve_sort_key,
        reverse=True,
    )
    db.add(
        MachineChange(
            machine_id=machine.id,
            detected_at=now or datetime.now(UTC),
            category="security",
            field=SECURITY_FIELD,
            old_value=None,
            new_value=_join(described),
        )
    )
    await db.commit()
    listing = "\n".join(f"- {line}" for line in described[:_MAX_LISTED])
    await notify(
        db,
        NotificationEventType.SECURITY_UPDATES_AVAILABLE,
        machine=machine,
        context={
            "package_count": str(len(packages)),
            "packages": listing,
            "cves": ", ".join(cves[:_MAX_LISTED]) or "—",
            "details": listing,
        },
    )
