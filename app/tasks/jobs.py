"""Background jobs processed by arq (queue in Redis)."""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, func, select

from app.audit import log_event
from app.core.app_settings import get_or_create_app_settings
from app.core.config import get_settings
from app.db.models.audit_log import AuditLogEntry
from app.db.models.machine import Machine
from app.db.models.machine_package import MachinePackage
from app.db.models.machine_update_run import MachineUpdateRun, UpdateRunStatus
from app.db.session import AsyncSessionLocal
from app.ssh.client import test_connection
from app.ssh.credentials import resolve_machine_credential
from app.ssh.exceptions import SSHConnectionError
from app.ssh.facts import gather_facts
from app.ssh.packages import gather_packages
from app.ssh.power import PowerAction, send_power_command
from app.ssh.reachability import check_reachable
from app.ssh.updates import check_updates, run_system_update

logger = logging.getLogger(__name__)

# Cap how many machines are checked/refreshed at once so one slow/firewalled
# host can't make a sweep over the whole fleet take forever.
_REACHABILITY_CONCURRENCY = 20

# Keep stored update output from growing unreasonably large for a very
# chatty apt run — keep the tail, since that's where errors/summaries land.
_MAX_STORED_OUTPUT_CHARS = 200_000


async def test_machine_connection(ctx: dict[str, Any], machine_id: str) -> dict[str, Any]:
    """Full SSH connection test for the "Test connection" button: connect
    (with strict pinned host-key verification) and run `uname -a`."""
    settings = get_settings()

    async with AsyncSessionLocal() as session:
        machine = await session.get(Machine, uuid.UUID(machine_id))
        if machine is None:
            return {"ok": False, "error": "Machine not found."}

        secret = await resolve_machine_credential(machine, session)

        try:
            output = await test_connection(machine, secret, settings.ssh_connect_timeout)
        except SSHConnectionError as exc:
            logger.warning("test_machine_connection failed for %s: %s", machine.name, exc)
            return {"ok": False, "error": str(exc)}

        return {"ok": True, "output": output}


async def ping_all_machines(ctx: dict[str, Any]) -> None:
    """Cheap per-minute reachability sweep (TCP connect only, no auth) for the
    status badge shown in the UI. Runs on a fixed one-minute cron schedule —
    see `app.tasks.worker.WorkerSettings.cron_jobs`."""
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(Machine).where(Machine.is_active))
        machines = list(result.scalars().all())
        if not machines:
            return

        semaphore = asyncio.Semaphore(_REACHABILITY_CONCURRENCY)

        async def _check(machine: Machine) -> tuple[Machine, bool]:
            async with semaphore:
                reachable = await check_reachable(machine.ip_address, machine.port)
                return machine, reachable

        results = await asyncio.gather(*(_check(m) for m in machines))

        now = datetime.now(UTC)
        for machine, reachable in results:
            machine.is_reachable = reachable
            machine.last_ping_at = now
        await session.commit()


async def refresh_machine_facts(ctx: dict[str, Any], machine_id: str) -> dict[str, Any]:
    """Connect to one machine and refresh its OS/kernel/hostname/CPU/RAM/disk
    facts. Requires a pinned host key — machines without one are skipped."""
    settings = get_settings()

    async with AsyncSessionLocal() as session:
        machine = await session.get(Machine, uuid.UUID(machine_id))
        if machine is None:
            return {"ok": False, "error": "Machine not found."}
        if not machine.host_key_fingerprint:
            return {"ok": False, "error": "No pinned host key fingerprint yet."}

        secret = await resolve_machine_credential(machine, session)

        try:
            facts = await gather_facts(machine, secret, settings.ssh_connect_timeout)
        except SSHConnectionError as exc:
            logger.warning("refresh_machine_facts failed for %s: %s", machine.name, exc)
            return {"ok": False, "error": str(exc)}

        machine.discovered_hostname = facts["hostname"]
        machine.os_version = facts["os_version"]
        machine.kernel_version = facts["kernel_version"]
        machine.cpu_cores = facts["cpu_cores"]
        machine.ram_bytes = facts["ram_bytes"]
        machine.disks = facts["disks"]
        machine.reboot_required = facts["reboot_required"]
        machine.facts_updated_at = datetime.now(UTC)
        await session.commit()

        return {"ok": True}


async def refresh_all_machine_facts(ctx: dict[str, Any]) -> None:
    """Periodic sweep scheduling a facts refresh for every machine with a
    pinned host key. Self-reschedules using `FACTS_REFRESH_INTERVAL_SECONDS`
    rather than a fixed cron schedule, since that interval is meant to be
    configurable.

    This only *enqueues* per-machine jobs rather than awaiting them inline,
    so a slow or unreachable machine can't make this scheduler job itself
    run long enough to hit arq's job timeout — each `refresh_machine_facts`
    job gets its own timeout budget instead.
    """
    settings = get_settings()
    redis = ctx["redis"]

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Machine.id).where(Machine.is_active, Machine.host_key_fingerprint.is_not(None))
        )
        machine_ids = [row[0] for row in result.all()]

    for machine_id in machine_ids:
        await redis.enqueue_job("refresh_machine_facts", str(machine_id))

    await redis.enqueue_job(
        "refresh_all_machine_facts",
        _defer_by=timedelta(seconds=settings.facts_refresh_interval_seconds),
    )


async def refresh_machine_packages(ctx: dict[str, Any], machine_id: str) -> dict[str, Any]:
    """Connect to one machine and refresh its installed-package snapshot
    (apt/flatpak/snap, with versions). Requires a pinned host key — machines
    without one are skipped. Replaces the machine's whole `MachinePackage`
    set in one transaction (delete-then-bulk-insert) rather than diffing,
    since this is a snapshot of "what's installed right now," not a
    history."""
    settings = get_settings()

    async with AsyncSessionLocal() as session:
        machine = await session.get(Machine, uuid.UUID(machine_id))
        if machine is None:
            return {"ok": False, "error": "Machine not found."}
        if not machine.host_key_fingerprint:
            return {"ok": False, "error": "No pinned host key fingerprint yet."}

        secret = await resolve_machine_credential(machine, session)

        try:
            packages = await gather_packages(machine, secret, settings.ssh_connect_timeout)
        except SSHConnectionError as exc:
            logger.warning("refresh_machine_packages failed for %s: %s", machine.name, exc)
            return {"ok": False, "error": str(exc)}

        await session.execute(
            delete(MachinePackage).where(MachinePackage.machine_id == machine.id)
        )
        session.add_all(
            MachinePackage(
                machine_id=machine.id,
                source=entry["source"],
                name=entry["name"],
                version=entry["version"],
            )
            for entry in packages
        )
        machine.packages_updated_at = datetime.now(UTC)
        await session.commit()

        return {"ok": True, "package_count": len(packages)}


async def refresh_all_machine_packages(ctx: dict[str, Any]) -> None:
    """Periodic sweep scheduling a package refresh for every machine with a
    pinned host key — same fan-out pattern (and the same
    `FACTS_REFRESH_INTERVAL_SECONDS` cadence) as `refresh_all_machine_facts`,
    for the same reason: this only enqueues, it never awaits the refreshes
    inline, so one slow/unreachable machine can't hold up the rest.
    """
    settings = get_settings()
    redis = ctx["redis"]

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Machine.id).where(Machine.is_active, Machine.host_key_fingerprint.is_not(None))
        )
        machine_ids = [row[0] for row in result.all()]

    for machine_id in machine_ids:
        await redis.enqueue_job("refresh_machine_packages", str(machine_id))

    await redis.enqueue_job(
        "refresh_all_machine_packages",
        _defer_by=timedelta(seconds=settings.facts_refresh_interval_seconds),
    )


def _truncate_output(output: str) -> str:
    if len(output) <= _MAX_STORED_OUTPUT_CHARS:
        return output
    return "[... output truncated ...]\n" + output[-_MAX_STORED_OUTPUT_CHARS:]


async def run_machine_update(ctx: dict[str, Any], run_id: str) -> None:
    """Execute one `MachineUpdateRun`: apt update, the chosen upgrade
    strategy, autoremove/autoclean, then flatpak/snap if installed — see
    `app.ssh.updates`.

    Given a long, dedicated timeout in `app.tasks.worker.WorkerSettings`
    (`UPDATE_TIMEOUT_SECONDS`), separate from the default job timeout used
    by every other job here.

    Once the run finishes (success or failure — the machine's packages and
    update counts may have changed either way, e.g. apt failed but flatpak/
    snap still updated), this enqueues a package-list refresh and a fresh
    update-availability check for the same machine, rather than waiting for
    the next periodic sweep, so the machine page reflects reality right away.
    """
    settings = get_settings()
    redis = ctx["redis"]

    async with AsyncSessionLocal() as session:
        run = await session.get(MachineUpdateRun, uuid.UUID(run_id))
        if run is None:
            return

        machine = await session.get(Machine, run.machine_id)
        if machine is None:
            run.status = UpdateRunStatus.FAILED
            run.error = "Machine not found."
            run.finished_at = datetime.now(UTC)
            await session.commit()
            return

        run.status = UpdateRunStatus.RUNNING
        run.started_at = datetime.now(UTC)
        await session.commit()

        secret = await resolve_machine_credential(machine, session)

        try:
            result = await run_system_update(
                machine,
                secret,
                run.strategy,
                settings.ssh_connect_timeout,
                settings.update_timeout_seconds,
            )
        except SSHConnectionError as exc:
            logger.warning("run_machine_update failed for %s: %s", machine.name, exc)
            run.status = UpdateRunStatus.FAILED
            run.error = str(exc)
        else:
            run.output = _truncate_output(result.output)
            if result.exit_status == 0:
                run.status = UpdateRunStatus.SUCCEEDED
            else:
                run.status = UpdateRunStatus.FAILED
                run.error = f"apt exited with status {result.exit_status}."

        run.finished_at = datetime.now(UTC)
        await session.commit()

    await redis.enqueue_job("refresh_machine_packages", str(run.machine_id))
    await redis.enqueue_job("check_machine_updates", str(run.machine_id))


async def check_machine_updates(ctx: dict[str, Any], machine_id: str) -> dict[str, Any]:
    """Dry-run: refresh the apt cache and record how many apt packages,
    flatpak apps, and snaps are upgradable, without installing anything.
    apt requires root/sudo, same as `run_machine_update`; flatpak/snap
    listing never does — see `app.ssh.updates`."""
    settings = get_settings()

    async with AsyncSessionLocal() as session:
        machine = await session.get(Machine, uuid.UUID(machine_id))
        if machine is None:
            return {"ok": False, "error": "Machine not found."}
        if not machine.host_key_fingerprint:
            return {"ok": False, "error": "No pinned host key fingerprint yet."}

        secret = await resolve_machine_credential(machine, session)

        try:
            result = await check_updates(
                machine, secret, settings.ssh_connect_timeout, settings.update_timeout_seconds
            )
        except SSHConnectionError as exc:
            logger.warning("check_machine_updates failed for %s: %s", machine.name, exc)
            return {"ok": False, "error": str(exc)}

        machine.updates_checked_at = datetime.now(UTC)
        # flatpak/snap listing runs independently of the apt step in the
        # remote script, so their counts are meaningful even when apt's
        # own refresh below failed — record them either way.
        machine.flatpak_upgradable_count = result.flatpak_upgradable_count
        machine.snap_upgradable_count = result.snap_upgradable_count

        if result.exit_status == 0:
            machine.upgradable_count = result.upgradable_count
            machine.security_upgradable_count = result.security_upgradable_count
            await session.commit()
            return {"ok": True}

        # `apt-get update` itself failed (commonly: no passwordless sudo
        # configured for this machine yet) — record that we tried and when,
        # but leave the apt counts as "unknown" rather than implying 0 updates.
        machine.upgradable_count = None
        machine.security_upgradable_count = None
        await session.commit()
        error = f"apt-get update exited with status {result.exit_status}."
        logger.warning("check_machine_updates failed for %s: %s", machine.name, error)
        return {"ok": False, "error": error}


async def check_all_machine_updates(ctx: dict[str, Any]) -> None:
    """Periodic sweep scheduling an update check for every machine with a
    pinned host key — same fan-out pattern (and the same
    `FACTS_REFRESH_INTERVAL_SECONDS` cadence) as `refresh_all_machine_facts`,
    for the same reason: this only enqueues, it never awaits the checks
    inline, so one slow/unreachable/misconfigured machine can't hold up the
    rest.
    """
    settings = get_settings()
    redis = ctx["redis"]

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Machine.id).where(Machine.is_active, Machine.host_key_fingerprint.is_not(None))
        )
        machine_ids = [row[0] for row in result.all()]

    for machine_id in machine_ids:
        await redis.enqueue_job("check_machine_updates", str(machine_id))

    await redis.enqueue_job(
        "check_all_machine_updates",
        _defer_by=timedelta(seconds=settings.facts_refresh_interval_seconds),
    )


async def send_machine_power_command(
    ctx: dict[str, Any], machine_id: str, action: str
) -> dict[str, Any]:
    """Reboot or shut down one machine. Fire-and-forget — see
    `app.ssh.power` for why there's no persistent result to report beyond
    ok/error; the reachability check reflects the actual outcome over the
    following minutes."""
    settings = get_settings()

    async with AsyncSessionLocal() as session:
        machine = await session.get(Machine, uuid.UUID(machine_id))
        if machine is None:
            return {"ok": False, "error": "Machine not found."}

        secret = await resolve_machine_credential(machine, session)

        try:
            await send_power_command(
                machine, secret, PowerAction(action), settings.ssh_connect_timeout
            )
        except SSHConnectionError as exc:
            logger.warning(
                "send_machine_power_command(%s) failed for %s: %s", action, machine.name, exc
            )
            return {"ok": False, "error": str(exc)}

        return {"ok": True}


_AUDIT_PURGE_ACTOR = "retention policy (automatic)"


async def purge_old_audit_log_entries(ctx: dict[str, Any]) -> None:
    """Delete audit log entries older than `AppSettings.
    audit_log_retention_days` — a fixed daily sweep, same shape as
    `ping_all_machines`, since "once a day" needs no configurable interval
    of its own (only *how many days to keep* is configurable, on the
    Settings page).

    Only ever deletes from the oldest end (`created_at < cutoff`), never
    from the middle — the hash chain's tip (`AuditChainState.last_hash`)
    always reflects the newest entry regardless of what's pruned from the
    beginning, so this can never invalidate `app.audit.verify_chain` for
    the entries that remain (see the Architecture wiki page). Skipped
    entirely when retention is unset (`None` = keep forever, the default).
    """
    async with AsyncSessionLocal() as session:
        app_settings = await get_or_create_app_settings(session)
        retention_days = app_settings.audit_log_retention_days
        if not retention_days:
            return

        cutoff = datetime.now(UTC) - timedelta(days=retention_days)
        count_result = await session.execute(
            select(func.count())
            .select_from(AuditLogEntry)
            .where(AuditLogEntry.created_at < cutoff)
        )
        deleted_count = count_result.scalar_one()
        if not deleted_count:
            return

        await session.execute(delete(AuditLogEntry).where(AuditLogEntry.created_at < cutoff))
        await session.commit()

        await log_event(
            session,
            actor=_AUDIT_PURGE_ACTOR,
            action="audit_log.purge",
            summary=(
                f"Purged {deleted_count} audit log entr"
                f"{'y' if deleted_count == 1 else 'ies'} older than "
                f"{retention_days} day(s)"
            ),
            details={"deleted_count": deleted_count, "retention_days": retention_days},
        )
