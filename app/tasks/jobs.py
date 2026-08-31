"""Background jobs processed by Celery (broker + result backend in Redis).

Every job in here follows the same two-part shape:

- `async def _do_the_thing(...)` — the real work. This app's logic is async
  all the way down (SQLAlchemy's async sessions, asyncssh), so that is where
  it lives.
- `@celery_app.task(name="...") def do_the_thing(...)` — a thin synchronous
  Celery task that does nothing but `asyncio.run(...)` the coroutine above.
  Celery tasks are synchronous; this is the seam between the two worlds, and
  it is deliberately kept to one line so there is never any logic that only
  exists on the sync side.

Task names are given explicitly and are a stable contract — see
`app.tasks.celery_app`'s module docstring.

DB sessions are always opened as `db_session.AsyncSessionLocal(...)` through
the module, never via a `from app.db.session import AsyncSessionLocal`
binding: each forked Celery worker child rebuilds that factory after the fork
(again, see `app.tasks.celery_app`), and a name captured at import time would
keep pointing at the parent's connection pool.
"""

from __future__ import annotations

import asyncio
import logging
import shlex
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, func, select

from app.audit import log_event
from app.core.app_settings import get_or_create_app_settings
from app.core.config import get_settings
from app.db import session as db_session
from app.db.models.audit_log import AuditLogEntry
from app.db.models.fleet_snapshot import FleetSnapshot
from app.db.models.machine import AuthMethod, Machine
from app.db.models.machine_package import MachinePackage
from app.db.models.machine_update_run import MachineUpdateRun, UpdateRunStatus, UpgradeStrategy
from app.services.fleet_stats import compute_fleet_stats
from app.ssh.client import test_connection
from app.ssh.credentials import resolve_machine_credential
from app.ssh.exceptions import SSHConnectionError
from app.ssh.exec import run_command
from app.ssh.facts import gather_facts
from app.ssh.identity import get_or_create_identity
from app.ssh.packages import gather_packages
from app.ssh.power import PowerAction, send_power_command
from app.ssh.reachability import check_reachable
from app.ssh.updates import check_updates, preview_update, run_system_update
from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)

# Cap how many machines are checked/refreshed at once so one slow/firewalled
# host can't make a sweep over the whole fleet take forever.
_REACHABILITY_CONCURRENCY = 20

# Keep stored update output from growing unreasonably large for a very
# chatty apt run — keep the tail, since that's where errors/summaries land.
_MAX_STORED_OUTPUT_CHARS = 200_000

# How often `_run_machine_update` is allowed to write apt's in-progress
# output to the DB — see `_persist_partial_output` inside it. Comfortably
# under the update-run page's 3s poll interval (`partials/
# update_run_status.html`) so a poll never has to wait an extra round trip
# to see the latest output.
_PROGRESS_COMMIT_INTERVAL_SECONDS = 2.0

# How long a one-shot `run_remote_ssh_command` may run for, on top of the
# connect timeout.
_SSH_COMMAND_EXTRA_SECONDS = 60


async def _test_machine_connection(machine_id: str) -> dict[str, Any]:
    """Full SSH connection test for the "Test connection" button: connect
    (with strict pinned host-key verification) and run `uname -a`."""
    settings = get_settings()

    async with db_session.AsyncSessionLocal() as session:
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


@celery_app.task(name="app.tasks.jobs.test_machine_connection")
def test_machine_connection(machine_id: str) -> dict[str, Any]:
    return asyncio.run(_test_machine_connection(machine_id))


async def _run_remote_ssh_command(machine_id: str, command: str) -> dict[str, Any]:
    """Run one arbitrary command on one machine and return its exit status
    and output — the execution half of the AI assistant's
    `run_ssh_command` tool (`app.ai.tools`).

    **This task performs no authorization of its own, and must never be
    enqueued from anywhere that hasn't done it.** Its only call site is the
    confirm route in `app.web.routes.ai`, which re-checks
    `Permission.ACTION_TERMINAL` on the confirming user immediately before
    enqueueing, after that user has seen the literal command string. That is
    the same trust boundary the interactive terminal has: reaching this
    point means a human with terminal rights asked for this exact command.
    """
    settings = get_settings()

    async with db_session.AsyncSessionLocal() as session:
        machine = await session.get(Machine, uuid.UUID(machine_id))
        if machine is None:
            return {"ok": False, "error": "Machine not found."}
        if not machine.host_key_fingerprint:
            return {"ok": False, "error": "No pinned host key fingerprint yet."}

        secret = await resolve_machine_credential(machine, session)

        try:
            result = await run_command(
                machine,
                secret,
                command,
                settings.ssh_connect_timeout,
                settings.ssh_connect_timeout + _SSH_COMMAND_EXTRA_SECONDS,
            )
        except SSHConnectionError as exc:
            logger.warning("run_remote_ssh_command failed for %s: %s", machine.name, exc)
            return {"ok": False, "error": str(exc)}

        return {
            "ok": True,
            "machine": machine.name,
            "exit_status": result.exit_status,
            "output": result.output,
        }


@celery_app.task(
    name="app.tasks.jobs.run_remote_ssh_command",
    # Deliberately far shorter than the apt tasks' `UPDATE_TIMEOUT_SECONDS`:
    # an ad-hoc command isn't expected to run for half an hour, and a
    # runaway one shouldn't tie up a worker child as if it were a
    # dist-upgrade. Long enough to connect plus a minute of work.
    time_limit=get_settings().ssh_connect_timeout + _SSH_COMMAND_EXTRA_SECONDS + 10,
)
def run_remote_ssh_command(machine_id: str, command: str) -> dict[str, Any]:
    return asyncio.run(_run_remote_ssh_command(machine_id, command))


async def _push_pending_ssh_key(machine_id: str) -> dict[str, Any]:
    """Append the app's *pending* (not yet activated) SSH public key to one
    machine's `~/.ssh/authorized_keys`, alongside the current one — the
    assisted alternative to copying it there by hand during key rotation
    (`app.ssh.identity`, `app/web/routes/settings.py`'s `/ssh-key/*`
    routes).

    Connects using the *currently active* credential
    (`resolve_machine_credential`) — that is what is already authorized on
    the machine; the point of this task is to add the new key next to it,
    not to switch to it. Only ever called for `AuthMethod.SSH_KEY`
    machines: a `PASSWORD`-auth machine doesn't use the app's shared
    identity at all, so there is nothing to push there.

    Idempotent: `grep -qxF` first, so running this again (e.g. retrying a
    partially-failed push) never duplicates the line.
    """
    async with db_session.AsyncSessionLocal() as session:
        machine = await session.get(Machine, uuid.UUID(machine_id))
        if machine is None:
            return {"ok": False, "error": "Machine not found."}
        if not machine.host_key_fingerprint:
            return {"ok": False, "error": "No pinned host key fingerprint yet."}
        if machine.auth_method != AuthMethod.SSH_KEY:
            return {"ok": False, "error": "Machine does not use the app's shared SSH key."}

        identity = await get_or_create_identity(session)
        pending_key = identity.pending_public_key
        if pending_key is None:
            return {"ok": False, "error": "No pending SSH key to push."}

        secret = await resolve_machine_credential(machine, session)
        settings = get_settings()
        quoted_key = shlex.quote(pending_key)
        command = (
            "mkdir -p ~/.ssh && chmod 700 ~/.ssh && "
            f"(grep -qxF {quoted_key} ~/.ssh/authorized_keys 2>/dev/null || "
            f"echo {quoted_key} >> ~/.ssh/authorized_keys) && "
            "chmod 600 ~/.ssh/authorized_keys"
        )

        try:
            result = await run_command(
                machine,
                secret,
                command,
                settings.ssh_connect_timeout,
                settings.ssh_connect_timeout + _SSH_COMMAND_EXTRA_SECONDS,
            )
        except SSHConnectionError as exc:
            logger.warning("push_pending_ssh_key failed for %s: %s", machine.name, exc)
            return {"ok": False, "error": str(exc)}

        if result.exit_status != 0:
            return {
                "ok": False,
                "error": f"Command exited {result.exit_status}: {result.output or '(no output)'}",
            }
        return {"ok": True, "machine": machine.name}


@celery_app.task(
    name="app.tasks.jobs.push_pending_ssh_key",
    # Same reasoning as run_remote_ssh_command above — a short, fixed
    # sequence of commands, not an apt run.
    time_limit=get_settings().ssh_connect_timeout + _SSH_COMMAND_EXTRA_SECONDS + 10,
)
def push_pending_ssh_key(machine_id: str) -> dict[str, Any]:
    return asyncio.run(_push_pending_ssh_key(machine_id))


async def _ping_all_machines() -> None:
    """Cheap reachability sweep (TCP connect only, no auth) for the status
    badge shown in the UI. Cadence is owned by Celery Beat
    (`REACHABILITY_CHECK_INTERVAL_SECONDS`, see `app.tasks.celery_app`) —
    this job just does the sweep and returns."""
    async with db_session.AsyncSessionLocal() as session:
        result = await session.execute(select(Machine).where(Machine.is_active))
        machines = list(result.scalars().all())
        if machines:
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


@celery_app.task(name="app.tasks.jobs.ping_all_machines")
def ping_all_machines() -> None:
    asyncio.run(_ping_all_machines())


async def _refresh_machine_facts(machine_id: str) -> dict[str, Any]:
    """Connect to one machine and refresh its OS/kernel/arch/CPU/RAM/disk/
    uptime/process-count facts. Requires a pinned host key — machines
    without one are skipped."""
    settings = get_settings()

    async with db_session.AsyncSessionLocal() as session:
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
        machine.cpu_architecture = facts["cpu_architecture"]
        machine.cpu_cores = facts["cpu_cores"]
        machine.ram_bytes = facts["ram_bytes"]
        machine.disks = facts["disks"]
        machine.reboot_required = facts["reboot_required"]
        machine.uptime_seconds = facts["uptime_seconds"]
        machine.process_count = facts["process_count"]
        machine.filesystems = facts["filesystems"]
        machine.network_interfaces = facts["network_interfaces"]
        machine.facts_updated_at = datetime.now(UTC)
        await session.commit()

        return {"ok": True}


@celery_app.task(name="app.tasks.jobs.refresh_machine_facts")
def refresh_machine_facts(machine_id: str) -> dict[str, Any]:
    return asyncio.run(_refresh_machine_facts(machine_id))


async def _refresh_all_machine_facts() -> None:
    """Periodic sweep scheduling a facts refresh for every machine with a
    pinned host key. Its cadence (`FACTS_REFRESH_INTERVAL_SECONDS`) is owned
    by Celery Beat — see `app.tasks.celery_app`.

    This only *enqueues* per-machine tasks rather than awaiting them inline,
    so a slow or unreachable machine can't make this sweep itself run long
    enough to hit the default task time limit — each `refresh_machine_facts`
    task gets its own budget instead.
    """
    async with db_session.AsyncSessionLocal() as session:
        result = await session.execute(
            select(Machine.id).where(Machine.is_active, Machine.host_key_fingerprint.is_not(None))
        )
        machine_ids = [row[0] for row in result.all()]

    for machine_id in machine_ids:
        refresh_machine_facts.delay(str(machine_id))


@celery_app.task(name="app.tasks.jobs.refresh_all_machine_facts")
def refresh_all_machine_facts() -> None:
    asyncio.run(_refresh_all_machine_facts())


async def _refresh_machine_packages(machine_id: str) -> dict[str, Any]:
    """Connect to one machine and refresh its installed-package snapshot
    (apt/flatpak/snap, with versions). Requires a pinned host key — machines
    without one are skipped. Replaces the machine's whole `MachinePackage`
    set in one transaction (delete-then-bulk-insert) rather than diffing,
    since this is a snapshot of "what's installed right now," not a
    history."""
    settings = get_settings()

    async with db_session.AsyncSessionLocal() as session:
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
                held=entry["held"],
            )
            for entry in packages
        )
        machine.packages_updated_at = datetime.now(UTC)
        await session.commit()

        return {"ok": True, "package_count": len(packages)}


@celery_app.task(name="app.tasks.jobs.refresh_machine_packages")
def refresh_machine_packages(machine_id: str) -> dict[str, Any]:
    return asyncio.run(_refresh_machine_packages(machine_id))


async def _refresh_all_machine_packages() -> None:
    """Periodic sweep scheduling a package refresh for every machine with a
    pinned host key — same fan-out pattern (and the same
    `FACTS_REFRESH_INTERVAL_SECONDS` Beat cadence) as
    `_refresh_all_machine_facts`, for the same reason: this only enqueues, it
    never awaits the refreshes inline, so one slow/unreachable machine can't
    hold up the rest.
    """
    async with db_session.AsyncSessionLocal() as session:
        result = await session.execute(
            select(Machine.id).where(Machine.is_active, Machine.host_key_fingerprint.is_not(None))
        )
        machine_ids = [row[0] for row in result.all()]

    for machine_id in machine_ids:
        refresh_machine_packages.delay(str(machine_id))


@celery_app.task(name="app.tasks.jobs.refresh_all_machine_packages")
def refresh_all_machine_packages() -> None:
    asyncio.run(_refresh_all_machine_packages())


def _truncate_output(output: str) -> str:
    if len(output) <= _MAX_STORED_OUTPUT_CHARS:
        return output
    return "[... output truncated ...]\n" + output[-_MAX_STORED_OUTPUT_CHARS:]


async def _run_machine_update(run_id: str) -> None:
    """Execute one `MachineUpdateRun`: apt update, the chosen upgrade
    strategy, autoremove/autoclean, then flatpak/snap if installed — see
    `app.ssh.updates`.

    Given a long, dedicated `time_limit` on its Celery task below
    (`UPDATE_TIMEOUT_SECONDS`), separate from the default task time limit
    used by every other job here.

    Once the run finishes (success or failure — the machine's packages and
    update counts may have changed either way, e.g. apt failed but flatpak/
    snap still updated), this enqueues a package-list refresh and a fresh
    update-availability check for the same machine, rather than waiting for
    the next periodic sweep, so the machine page reflects reality right away.
    """
    settings = get_settings()

    async with db_session.AsyncSessionLocal() as session:
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

        # Persists apt's output as it arrives, so the update-run page (which
        # polls `partials/update_run_status.html` every 3s) shows it live
        # instead of only once the whole run has finished. Throttled to at
        # most once per _PROGRESS_COMMIT_INTERVAL_SECONDS — apt can emit
        # output far faster than that, and every call here is a DB write.
        last_progress_commit = 0.0

        async def _persist_partial_output(text: str) -> None:
            nonlocal last_progress_commit
            now = time.monotonic()
            if now - last_progress_commit < _PROGRESS_COMMIT_INTERVAL_SECONDS:
                return
            last_progress_commit = now
            run.output = _truncate_output(text)
            await session.commit()

        try:
            result = await run_system_update(
                machine,
                secret,
                run.strategy,
                settings.ssh_connect_timeout,
                settings.update_timeout_seconds,
                on_output=_persist_partial_output,
            )
        except (SSHConnectionError, TimeoutError) as exc:
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

    refresh_machine_packages.delay(str(run.machine_id))
    check_machine_updates.delay(str(run.machine_id))


@celery_app.task(
    name="app.tasks.jobs.run_machine_update",
    time_limit=get_settings().update_timeout_seconds,
)
def run_machine_update(run_id: str) -> None:
    asyncio.run(_run_machine_update(run_id))


async def _check_machine_updates(machine_id: str) -> dict[str, Any]:
    """Dry-run: refresh the apt cache and record how many apt packages,
    flatpak apps, and snaps are upgradable, without installing anything.
    apt requires root/sudo, same as `run_machine_update`; flatpak/snap
    listing never does — see `app.ssh.updates`."""
    settings = get_settings()

    async with db_session.AsyncSessionLocal() as session:
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
        # remote script, so their counts/lists are meaningful even when
        # apt's own refresh below failed — record them either way.
        machine.flatpak_upgradable_count = result.flatpak_upgradable_count
        machine.snap_upgradable_count = result.snap_upgradable_count
        machine.flatpak_upgradable_packages = [dict(p) for p in result.flatpak_upgradable_packages]
        machine.snap_upgradable_packages = [dict(p) for p in result.snap_upgradable_packages]

        if result.exit_status == 0:
            machine.upgradable_count = result.upgradable_count
            machine.security_upgradable_count = result.security_upgradable_count
            machine.apt_upgradable_packages = [dict(p) for p in result.apt_upgradable_packages]
            await session.commit()
            return {"ok": True}

        # `apt-get update` itself failed (commonly: no passwordless sudo
        # configured for this machine yet) — record that we tried and when,
        # but leave the apt counts/list as "unknown" rather than implying 0
        # updates.
        machine.upgradable_count = None
        machine.security_upgradable_count = None
        machine.apt_upgradable_packages = None
        await session.commit()
        error = f"apt-get update exited with status {result.exit_status}."
        logger.warning("check_machine_updates failed for %s: %s", machine.name, error)
        return {"ok": False, "error": error}


@celery_app.task(
    name="app.tasks.jobs.check_machine_updates",
    time_limit=get_settings().update_timeout_seconds,
)
def check_machine_updates(machine_id: str) -> dict[str, Any]:
    return asyncio.run(_check_machine_updates(machine_id))


async def _preview_machine_update(machine_id: str, strategy: str) -> dict[str, Any]:
    """Dry-run preview for the manual "Run update" flow
    (`GET /machines/{id}/updates/preview` in `app/web/routes/machines.py`):
    simulate the exact update sequence with apt's `-s` flag and report what
    would be installed/upgraded and, especially, what `autoremove` would
    remove — without changing anything on the machine. Nothing is persisted
    to the `Machine` row here (unlike `check_machine_updates` above) — this
    is a one-off, ephemeral view for whoever's looking at the preview page
    right now, not a fact worth keeping around after they navigate away."""
    settings = get_settings()

    async with db_session.AsyncSessionLocal() as session:
        machine = await session.get(Machine, uuid.UUID(machine_id))
        if machine is None:
            return {"ok": False, "error": "Machine not found."}
        if not machine.host_key_fingerprint:
            return {"ok": False, "error": "No pinned host key fingerprint yet."}

        secret = await resolve_machine_credential(machine, session)

        try:
            result = await preview_update(
                machine,
                secret,
                UpgradeStrategy(strategy),
                settings.ssh_connect_timeout,
                settings.update_timeout_seconds,
            )
        except SSHConnectionError as exc:
            logger.warning("preview_machine_update failed for %s: %s", machine.name, exc)
            return {"ok": False, "error": str(exc)}

    if result.exit_status != 0:
        error = f"apt-get update exited with status {result.exit_status} while previewing."
        logger.warning("preview_machine_update failed for %s: %s", machine.name, error)
        return {"ok": False, "error": error}

    return {
        "ok": True,
        "to_install_or_upgrade": [dict(p) for p in result.to_install_or_upgrade],
        "to_remove": [dict(p) for p in result.to_remove],
    }


@celery_app.task(
    name="app.tasks.jobs.preview_machine_update",
    time_limit=get_settings().update_timeout_seconds,
)
def preview_machine_update(machine_id: str, strategy: str) -> dict[str, Any]:
    return asyncio.run(_preview_machine_update(machine_id, strategy))


async def _check_all_machine_updates() -> None:
    """Periodic sweep scheduling an update check for every machine with a
    pinned host key — same fan-out pattern (and the same
    `FACTS_REFRESH_INTERVAL_SECONDS` Beat cadence) as
    `_refresh_all_machine_facts`, for the same reason: this only enqueues, it
    never awaits the checks inline, so one slow/unreachable/misconfigured
    machine can't hold up the rest.
    """
    async with db_session.AsyncSessionLocal() as session:
        result = await session.execute(
            select(Machine.id).where(Machine.is_active, Machine.host_key_fingerprint.is_not(None))
        )
        machine_ids = [row[0] for row in result.all()]

    for machine_id in machine_ids:
        check_machine_updates.delay(str(machine_id))


@celery_app.task(name="app.tasks.jobs.check_all_machine_updates")
def check_all_machine_updates() -> None:
    asyncio.run(_check_all_machine_updates())


async def _send_machine_power_command(machine_id: str, action: str) -> dict[str, Any]:
    """Reboot or shut down one machine. Fire-and-forget — see
    `app.ssh.power` for why there's no persistent result to report beyond
    ok/error; the reachability check reflects the actual outcome over the
    following minutes."""
    settings = get_settings()

    async with db_session.AsyncSessionLocal() as session:
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


@celery_app.task(name="app.tasks.jobs.send_machine_power_command")
def send_machine_power_command(machine_id: str, action: str) -> dict[str, Any]:
    return asyncio.run(_send_machine_power_command(machine_id, action))


_AUDIT_PURGE_ACTOR = "retention policy (automatic)"


async def _purge_old_audit_log_entries() -> None:
    """Delete audit log entries older than `AppSettings.
    audit_log_retention_days` — a fixed daily sweep, same shape as
    the other Beat-driven sweeps, since "once a day" needs no configurable
    interval of its own (only *how many days to keep* is configurable, on the
    Settings page).

    Only ever deletes from the oldest end (`created_at < cutoff`), never
    from the middle — the hash chain's tip (`AuditChainState.last_hash`)
    always reflects the newest entry regardless of what's pruned from the
    beginning, so this can never invalidate `app.audit.verify_chain` for
    the entries that remain (see the Architecture wiki page). Skipped
    entirely when retention is unset (`None` = keep forever, the default).
    """
    async with db_session.AsyncSessionLocal() as session:
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


@celery_app.task(name="app.tasks.jobs.purge_old_audit_log_entries")
def purge_old_audit_log_entries() -> None:
    asyncio.run(_purge_old_audit_log_entries())


async def _record_fleet_snapshot() -> None:
    """Write today's fleet-wide snapshot row (Task 4's Dashboard trend
    chart), using the exact same queries the live Dashboard shows
    (`app.services.fleet_stats.compute_fleet_stats`) so the trend line and
    the current numbers can never disagree on what they mean.

    A fixed once-a-day Beat entry (see `app.tasks.celery_app`), same idea as
    `purge_old_audit_log_entries` — only *how long to keep* snapshots is
    configurable (Settings), not this cadence. Idempotent per calendar day:
    if today's row already exists (e.g. the beat process restarted and
    re-fired the entry), this is a no-op rather than a second
    row for the same day — `FleetSnapshot.snapshot_date` is also uniquely
    constrained at the DB level as a second line of defense.

    Not audit-logged — same reasoning as the other routine, unattended
    sweeps in this module (see wiki/Development.md's "Recording a new
    action in the audit log").
    """
    async with db_session.AsyncSessionLocal() as session:
        today = datetime.now(UTC).date()
        existing = await session.scalar(
            select(FleetSnapshot).where(FleetSnapshot.snapshot_date == today)
        )
        if existing is not None:
            return

        stats = await compute_fleet_stats(session)
        session.add(
            FleetSnapshot(
                snapshot_date=today,
                total_machines=stats["total"],
                online_machines=stats["online"],
                offline_machines=stats["offline"],
                needs_updates=stats["needs_updates"],
                needs_security_updates=stats["needs_security_updates"],
                needs_reboot=stats["needs_reboot"],
            )
        )
        await session.commit()


@celery_app.task(name="app.tasks.jobs.record_fleet_snapshot")
def record_fleet_snapshot() -> None:
    asyncio.run(_record_fleet_snapshot())


_FLEET_SNAPSHOT_PURGE_ACTOR = "retention policy (automatic)"


async def _purge_old_fleet_snapshots() -> None:
    """Delete `FleetSnapshot` rows older than `AppSettings.
    dashboard_trends_retention_days` — same shape as
    `purge_old_audit_log_entries` above, including being skipped entirely
    when retention is unset (`None` = keep forever)."""
    async with db_session.AsyncSessionLocal() as session:
        app_settings = await get_or_create_app_settings(session)
        retention_days = app_settings.dashboard_trends_retention_days
        if not retention_days:
            return

        cutoff = (datetime.now(UTC) - timedelta(days=retention_days)).date()
        count_result = await session.execute(
            select(func.count())
            .select_from(FleetSnapshot)
            .where(FleetSnapshot.snapshot_date < cutoff)
        )
        deleted_count = count_result.scalar_one()
        if not deleted_count:
            return

        await session.execute(
            delete(FleetSnapshot).where(FleetSnapshot.snapshot_date < cutoff)
        )
        await session.commit()

        await log_event(
            session,
            actor=_FLEET_SNAPSHOT_PURGE_ACTOR,
            action="dashboard_trends.purge",
            summary=(
                f"Purged {deleted_count} fleet snapshot"
                f"{'s' if deleted_count != 1 else ''} older than {retention_days} day(s)"
            ),
            details={"deleted_count": deleted_count, "retention_days": retention_days},
        )


@celery_app.task(name="app.tasks.jobs.purge_old_fleet_snapshots")
def purge_old_fleet_snapshots() -> None:
    asyncio.run(_purge_old_fleet_snapshots())
