"""Machine health notifications: what changed for the worse since the last
look — a reboot became necessary, a disk's S.M.A.R.T. health failed, a
systemd unit failed, a filesystem is forecast to fill up soon, a ZFS pool
left ONLINE, a Proxmox VE backup failed.

Each check compares the value about to be stored with the one already on
the machine (or its previous monitoring sample) and notifies only on the
transition — never on every sample while the state persists, and never
when the previous value is unknown (a machine's first refresh, or the
first one after an upgrade that started collecting it), so an upgrade
doesn't page anyone about problems that were already there.

The comparisons are pure functions; `app.tasks.jobs` calls the `notify_*`
wrappers from the facts refresh, the monitoring sample and the hourly
disk forecast. Also: a Proxmox Backup Server job/task failing (reported
as a failed backup), a Mail Gateway's queue backing up, and a Proxmox VE
cluster losing quorum.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.machine import Machine
from app.db.models.notification_rule import NotificationEventType
from app.services.disk_forecast import soonest_full_days
from app.services.notifications import notify
from app.ssh import proxmox

# "Disk will be full in X days" fires once a filesystem's forecast drops to
# this many days or fewer (a condition rule on "days until a filesystem is
# full" covers any other threshold).
DISK_FULL_WARN_DAYS = 7


def became_reboot_required(previous: bool | None, current: bool | None) -> bool:
    return previous is False and current is True


def newly_failed_units(previous: list[str] | None, current: list[str] | None) -> list[str]:
    if previous is None or current is None:
        return []
    before = set(previous)
    return [unit for unit in current if unit not in before]


def _failing_disks(smart_disks: Iterable[dict[str, Any]] | None) -> set[str]:
    return {str(d.get("device")) for d in smart_disks or [] if d.get("healthy") is False}


def newly_failing_disks(
    previous: list[dict[str, Any]] | None, current: list[dict[str, Any]] | None
) -> list[str]:
    if previous is None or current is None:
        return []
    return sorted(_failing_disks(current) - _failing_disks(previous))


def _unhealthy(pools: Iterable[dict[str, Any]] | None) -> dict[str, dict[str, Any]]:
    return {str(p.get("name")): p for p in pools or [] if str(p.get("health")) != "ONLINE"}


def newly_unhealthy_pools(
    previous: list[dict[str, Any]] | None, current: list[dict[str, Any]] | None
) -> list[dict[str, Any]]:
    if previous is None or current is None:
        return []
    before = _unhealthy(previous)
    return [pool for name, pool in _unhealthy(current).items() if name not in before]


def _failed_tasks(backups: dict[str, Any] | None) -> dict[tuple[Any, str], dict[str, Any]]:
    return {
        (task.get("started_at"), str(task.get("id") or "")): task
        for task in (backups or {}).get("tasks") or []
        if task.get("ok") is False
    }


def new_failed_backups(
    previous: dict[str, Any] | None, current: dict[str, Any] | None
) -> list[dict[str, Any]]:
    if previous is None or current is None:
        return []
    before = _failed_tasks(previous)
    return [task for key, task in _failed_tasks(current).items() if key not in before]


def disk_full_crossed(
    previous: dict[str, Any] | None, current: dict[str, Any] | None
) -> tuple[str, float] | None:
    """(mount, days) when the soonest-full filesystem just dropped to
    `DISK_FULL_WARN_DAYS` or fewer; None otherwise."""
    now_days = soonest_full_days(current)
    if now_days is None or now_days > DISK_FULL_WARN_DAYS:
        return None
    before_days = soonest_full_days(previous)
    if before_days is not None and before_days <= DISK_FULL_WARN_DAYS:
        return None
    for mount, forecast in (current or {}).items():
        if forecast.get("days_until_full") == now_days:
            return mount, now_days
    return "?", now_days


def new_pbs_failures(
    previous: dict[str, Any] | None, current: dict[str, Any] | None
) -> list[str]:
    """Proxmox Backup Server job/task failures not already failing at the
    previous refresh."""
    if previous is None or current is None:
        return []
    before = set(proxmox.pbs_failures(previous))
    return [line for line in proxmox.pbs_failures(current) if line not in before]


def mail_queue_crossed(previous: dict[str, Any] | None, current: dict[str, Any] | None) -> int:
    """The deferred/held message count when a Mail Gateway's queue just
    reached `proxmox.MAIL_QUEUE_WARN`; 0 otherwise."""
    if previous is None or current is None:
        return 0
    now = proxmox.mail_queue_backlog(current)
    if (
        now < proxmox.MAIL_QUEUE_WARN
        or proxmox.mail_queue_backlog(previous) >= proxmox.MAIL_QUEUE_WARN
    ):
        return 0
    return now


def lost_quorum(previous: dict[str, Any] | None, current: dict[str, Any] | None) -> bool:
    return bool(previous and current and previous.get("quorate") is True
                and current.get("quorate") is False)


async def notify_facts_changes(
    db: AsyncSession,
    machine: Machine,
    *,
    previous_reboot_required: bool | None,
    previous_backups: dict[str, Any] | None,
    previous_pbs: dict[str, Any] | None = None,
    previous_pmg: dict[str, Any] | None = None,
) -> None:
    """After a facts refresh has stored its new values on `machine`."""
    if became_reboot_required(previous_reboot_required, machine.reboot_required):
        await notify(
            db,
            NotificationEventType.REBOOT_REQUIRED,
            machine=machine,
            context={"details": f"Running kernel: {machine.kernel_version or 'unknown'}"},
        )
    failed = new_failed_backups(previous_backups, machine.pve_backups)
    pbs_lines = new_pbs_failures(previous_pbs, machine.pbs_data)
    if failed or pbs_lines:
        lines = [f"{t.get('id') or 'backup job'}: {t.get('status')}" for t in failed]
        lines += pbs_lines
        await notify(
            db,
            NotificationEventType.BACKUP_FAILED,
            machine=machine,
            context={"details": "\n".join(lines)},
        )
    backlog = mail_queue_crossed(previous_pmg, machine.pmg_data)
    if backlog:
        await notify(
            db,
            NotificationEventType.MAIL_QUEUE_BACKLOG,
            machine=machine,
            context={"count": str(backlog), "details": ""},
        )


async def notify_monitoring_changes(
    db: AsyncSession,
    machine: Machine,
    *,
    previous_failed_units: list[str] | None,
    previous_smart_disks: list[dict[str, Any]] | None,
    current_smart_disks: list[dict[str, Any]] | None,
    previous_zfs_pools: list[dict[str, Any]] | None,
    previous_cluster: dict[str, Any] | None = None,
) -> None:
    """After a monitoring sample has been stored."""
    if lost_quorum(previous_cluster, machine.pve_cluster):
        cluster = machine.pve_cluster or {}
        offline = [n["name"] for n in cluster.get("nodes") or [] if not n.get("online")]
        await notify(
            db,
            NotificationEventType.CLUSTER_QUORUM_LOST,
            machine=machine,
            context={
                "cluster": str(cluster.get("name") or ""),
                "details": "Offline nodes: " + (", ".join(offline) or "none reported"),
            },
        )
    units = newly_failed_units(previous_failed_units, machine.failed_units)
    if units:
        await notify(
            db,
            NotificationEventType.SERVICE_FAILED,
            machine=machine,
            context={"units": ", ".join(units), "details": "\n".join(units)},
        )
    disks = newly_failing_disks(previous_smart_disks, current_smart_disks)
    if disks:
        await notify(
            db,
            NotificationEventType.SMART_FAILED,
            machine=machine,
            context={"devices": ", ".join(disks), "details": ", ".join(disks)},
        )
    pools = newly_unhealthy_pools(previous_zfs_pools, machine.zfs_pools)
    if pools:
        lines = [
            f"{p.get('name')}: {p.get('health')} {p.get('status') or ''}".strip() for p in pools
        ]
        await notify(
            db,
            NotificationEventType.ZFS_POOL_UNHEALTHY,
            machine=machine,
            context={
                "pools": ", ".join(str(p.get("name")) for p in pools),
                "details": "\n".join(lines),
            },
        )


async def notify_forecast_change(
    db: AsyncSession, machine: Machine, *, previous_forecast: dict[str, Any] | None
) -> None:
    """After the hourly disk forecast has been stored."""
    crossed = disk_full_crossed(previous_forecast, machine.disk_forecast)
    if crossed is None:
        return
    mount, days = crossed
    await notify(
        db,
        NotificationEventType.DISK_FULL_PREDICTED,
        machine=machine,
        context={"mount": mount, "days": f"{days:.0f}", "details": ""},
    )
