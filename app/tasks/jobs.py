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
import json
import logging
import shlex
import time
import uuid
from collections.abc import Callable
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
from app.db.models.machine_monitoring_sample import MachineMonitoringSample
from app.db.models.machine_package import MachinePackage
from app.db.models.machine_reachability_sample import MachineReachabilitySample
from app.db.models.machine_service import MachineService
from app.db.models.machine_update_run import MachineUpdateRun, UpdateRunStatus, UpgradeStrategy
from app.db.models.notification_rule import NotificationEventType
from app.services.fleet_stats import compute_fleet_stats
from app.services.live_updates import (
    KIND_FACTS,
    KIND_PACKAGES,
    KIND_SERVICES,
    KIND_STATUS,
    KIND_UPDATES,
    publish_machine_event,
)
from app.services.notifications import notify
from app.ssh.client import test_connection
from app.ssh.credentials import resolve_machine_credential
from app.ssh.exceptions import SSHConnectionError
from app.ssh.exec import run_command
from app.ssh.facts import gather_facts
from app.ssh.identity import get_or_create_identity
from app.ssh.logs import LogAccessError, list_directory, view_file, view_journal
from app.ssh.monitoring import gather_monitoring_sample
from app.ssh.onboarding import ONBOARD_SUCCESS_MARKER, ONBOARD_USERNAME, build_onboarding_command
from app.ssh.packages import gather_packages
from app.ssh.power import PowerAction, send_power_command
from app.ssh.reachability import ReachabilityResult, check_reachable
from app.ssh.readiness import DIRECT_FIX_COMMAND, missing_requirements
from app.ssh.readiness import check_machine_readiness as run_readiness_probes
from app.ssh.services import gather_services
from app.ssh.updates import (
    capture_package_snapshot,
    check_updates,
    preview_update,
    run_rollback,
    run_system_update,
)
from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)


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
    `run_ssh_command` tool (`app.ai.tools`), and of the `run_command`
    scheduled action (`app.scheduling.builtin_actions`, via
    `app.services.machine_actions.run_custom_command_on_machines`).

    **This task performs no authorization of its own, and must never be
    enqueued from anywhere that hasn't done it.** Two call sites, two
    different points in time where that authorization happens:
    - The confirm route in `app.web.routes.ai`, which re-checks
      `Permission.ACTION_TERMINAL` on the confirming user immediately
      before enqueueing, after that user has seen the literal command
      string — the same trust boundary the interactive terminal has:
      reaching this point means a human with terminal rights asked for
      this exact command, right now.
    - A `run_command` scheduled task, authorized once at creation/edit
      time (`app.web.routes.scheduling` requires `action.terminal` in
      addition to `scheduling.manage` for that one action) rather than at
      every fire — the same "authorized when set up, then runs
      unattended" shape `reboot`/`shutdown`/`system_update` scheduled
      actions already have.
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


async def _view_machine_journal(
    machine_id: str, *, lines: int, search: str, since: str, until: str
) -> dict[str, Any]:
    """The Logs tab's default view — no persistence, a fresh read-only SSH
    round trip every time (see `app.ssh.logs`'s module docstring for the
    permission-tier reasoning)."""
    settings = get_settings()

    async with db_session.AsyncSessionLocal() as session:
        machine = await session.get(Machine, uuid.UUID(machine_id))
        if machine is None:
            return {"ok": False, "error": "Machine not found."}
        if not machine.host_key_fingerprint:
            return {"ok": False, "error": "No pinned host key fingerprint yet."}

        secret = await resolve_machine_credential(machine, session)

        try:
            output = await view_journal(
                machine,
                secret,
                settings.ssh_connect_timeout,
                lines=lines,
                search=search,
                since=since,
                until=until,
            )
        except SSHConnectionError as exc:
            logger.warning("view_machine_journal failed for %s: %s", machine.name, exc)
            return {"ok": False, "error": str(exc)}

        return {"ok": True, "output": output}


@celery_app.task(
    name="app.tasks.jobs.view_machine_journal",
    time_limit=get_settings().ssh_connect_timeout + _SSH_COMMAND_EXTRA_SECONDS,
)
def view_machine_journal(
    machine_id: str, *, lines: int, search: str, since: str, until: str
) -> dict[str, Any]:
    return asyncio.run(
        _view_machine_journal(machine_id, lines=lines, search=search, since=since, until=until)
    )


async def _view_machine_log_file(
    machine_id: str, *, path: str, lines: int, search: str
) -> dict[str, Any]:
    """The Logs tab's "view a file" mode — restricted to `LOG_FILE_ALLOWED_
    PATHS`, checked inside `view_file` itself (never reaches the machine at
    all for a disallowed path)."""
    settings = get_settings()

    async with db_session.AsyncSessionLocal() as session:
        machine = await session.get(Machine, uuid.UUID(machine_id))
        if machine is None:
            return {"ok": False, "error": "Machine not found."}
        if not machine.host_key_fingerprint:
            return {"ok": False, "error": "No pinned host key fingerprint yet."}

        secret = await resolve_machine_credential(machine, session)

        try:
            output = await view_file(
                machine, secret, settings.ssh_connect_timeout, path=path, lines=lines, search=search
            )
        except LogAccessError as exc:
            return {"ok": False, "error": str(exc)}
        except SSHConnectionError as exc:
            logger.warning("view_machine_log_file failed for %s: %s", machine.name, exc)
            return {"ok": False, "error": str(exc)}

        return {"ok": True, "output": output}


@celery_app.task(
    name="app.tasks.jobs.view_machine_log_file",
    time_limit=get_settings().ssh_connect_timeout + _SSH_COMMAND_EXTRA_SECONDS,
)
def view_machine_log_file(machine_id: str, *, path: str, lines: int, search: str) -> dict[str, Any]:
    return asyncio.run(_view_machine_log_file(machine_id, path=path, lines=lines, search=search))


async def _browse_machine_log_directory(machine_id: str, *, path: str) -> dict[str, Any]:
    """The Logs tab's "browse" picker — list what's directly inside an
    allowed directory instead of requiring the exact file path to already be
    known. Same `LOG_FILE_ALLOWED_PATHS` restriction as `view_file`, checked
    inside `list_directory` itself (never reaches the machine at all for a
    disallowed path)."""
    settings = get_settings()

    async with db_session.AsyncSessionLocal() as session:
        machine = await session.get(Machine, uuid.UUID(machine_id))
        if machine is None:
            return {"ok": False, "error": "Machine not found."}
        if not machine.host_key_fingerprint:
            return {"ok": False, "error": "No pinned host key fingerprint yet."}

        secret = await resolve_machine_credential(machine, session)

        try:
            entries = await list_directory(
                machine, secret, settings.ssh_connect_timeout, path=path
            )
        except LogAccessError as exc:
            return {"ok": False, "error": str(exc)}
        except SSHConnectionError as exc:
            logger.warning("browse_machine_log_directory failed for %s: %s", machine.name, exc)
            return {"ok": False, "error": str(exc)}

        return {"ok": True, "entries": [{"name": n, "is_dir": d} for n, d in entries]}


@celery_app.task(
    name="app.tasks.jobs.browse_machine_log_directory",
    time_limit=get_settings().ssh_connect_timeout + _SSH_COMMAND_EXTRA_SECONDS,
)
def browse_machine_log_directory(machine_id: str, *, path: str) -> dict[str, Any]:
    return asyncio.run(_browse_machine_log_directory(machine_id, path=path))


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


# The onboarding script does a handful of local operations (useradd, a few
# file writes) plus one `apt-get update && apt-get install` — give it more
# headroom than the plain-local-commands push above.
_ONBOARDING_EXTRA_SECONDS = 90


async def _run_machine_onboarding(machine_id: str) -> dict[str, Any]:
    """Prepares a freshly-added, not-yet-managed machine for debcontrol —
    see `app.ssh.onboarding` for exactly what the script does and why this
    isn't a real `ansible-playbook` invocation.

    Connects using the *currently stored* credential — the one-time root
    (or root-equivalent) login the operator entered when adding this
    machine (`POST /machines`, same as any other machine — see
    `app.web.routes.machines.run_onboarding_endpoint`), since the whole
    point is to bootstrap a machine that has nothing configured for
    debcontrol's own shared identity yet. On success, switches the machine
    over to that identity (`username="debcontrol"`, `auth_method=SSH_KEY`,
    clearing the stored one-time secret) so every other feature (updates,
    terminal, power, ...) treats it exactly like any other SSH_KEY machine
    from then on — there is no separate "onboarded" flag to track.

    Requires a pinned host key fingerprint first, same as every other
    real connection this app makes — onboarding a machine is not an
    exception to "no trust on first use."
    """
    settings = get_settings()

    async with db_session.AsyncSessionLocal() as session:
        machine = await session.get(Machine, uuid.UUID(machine_id))
        if machine is None:
            return {"ok": False, "error": "Machine not found."}
        if not machine.host_key_fingerprint:
            return {"ok": False, "error": "No pinned host key fingerprint yet."}

        secret = await resolve_machine_credential(machine, session)
        identity = await get_or_create_identity(session)
        script = build_onboarding_command(identity.public_key)

        try:
            result = await run_command(
                machine,
                secret,
                script,
                settings.ssh_connect_timeout,
                settings.ssh_connect_timeout + _ONBOARDING_EXTRA_SECONDS,
            )
        except SSHConnectionError as exc:
            logger.warning("run_machine_onboarding failed for %s: %s", machine.name, exc)
            return {"ok": False, "error": str(exc)}

        if result.exit_status != 0 or ONBOARD_SUCCESS_MARKER not in result.output:
            return {
                "ok": False,
                "error": (
                    f"Setup script exited {result.exit_status}: "
                    f"{result.output or '(no output)'}"
                ),
            }

        machine.username = ONBOARD_USERNAME
        machine.auth_method = AuthMethod.SSH_KEY
        machine.secret_encrypted = None
        await session.commit()

        return {"ok": True, "output": result.output}


@celery_app.task(
    name="app.tasks.jobs.run_machine_onboarding",
    time_limit=get_settings().ssh_connect_timeout + _ONBOARDING_EXTRA_SECONDS + 15,
)
def run_machine_onboarding(machine_id: str) -> dict[str, Any]:
    return asyncio.run(_run_machine_onboarding(machine_id))


async def _check_machine_readiness(machine_id: str) -> dict[str, Any]:
    """Runs `app.ssh.readiness`'s probes against one machine and stores the
    result on it (`Machine.readiness_checked_at`/`readiness_missing`) —
    not returned for its own sake to a caller blocking on this task's
    result the way most other tasks here are; every caller either fires
    this and forgets it (right after a host key is confirmed) or reloads
    the machine from the DB afterward (the "Re-check" button, the
    onboarding-with-credential route)."""
    settings = get_settings()

    async with db_session.AsyncSessionLocal() as session:
        machine = await session.get(Machine, uuid.UUID(machine_id))
        if machine is None:
            return {"ok": False, "error": "Machine not found."}
        if not machine.host_key_fingerprint:
            return {"ok": False, "error": "No pinned host key fingerprint yet."}

        secret = await resolve_machine_credential(machine, session)

        try:
            result = await run_readiness_probes(machine, secret, settings.ssh_connect_timeout)
        except SSHConnectionError as exc:
            logger.warning("check_machine_readiness failed for %s: %s", machine.name, exc)
            return {"ok": False, "error": str(exc)}

        machine.readiness_missing = missing_requirements(result)
        machine.readiness_checked_at = datetime.now(UTC)
        await session.commit()

        return {"ok": True, "missing": machine.readiness_missing}


@celery_app.task(
    name="app.tasks.jobs.check_machine_readiness",
    time_limit=get_settings().ssh_connect_timeout + 30,
)
def check_machine_readiness(machine_id: str) -> dict[str, Any]:
    return asyncio.run(_check_machine_readiness(machine_id))


async def _fix_root_readiness(machine_id: str) -> dict[str, Any]:
    """Installs `ncurses-term` directly, using the machine's own
    already-configured credential — the readiness banner's "Install now"
    button for a machine that's connected as root (see
    `app.web.routes.machines.fix_readiness_directly_endpoint`, the only
    caller). No fresh credential, no sudoers file, no new user: every
    *other* readiness requirement is a sudo grant a root account never
    needs (`app.ssh.readiness`'s module docstring), so this is the only
    thing left for a root-connected machine to actually fix. Re-runs the
    readiness probes afterward either way, so the banner reflects reality
    even if the install itself failed (no network, no matching package)."""
    settings = get_settings()

    async with db_session.AsyncSessionLocal() as session:
        machine = await session.get(Machine, uuid.UUID(machine_id))
        if machine is None:
            return {"ok": False, "error": "Machine not found."}
        if not machine.host_key_fingerprint:
            return {"ok": False, "error": "No pinned host key fingerprint yet."}

        secret = await resolve_machine_credential(machine, session)
        try:
            await run_command(
                machine,
                secret,
                DIRECT_FIX_COMMAND,
                settings.ssh_connect_timeout,
                settings.ssh_connect_timeout + 30,
            )
        except SSHConnectionError as exc:
            logger.warning("fix_root_readiness failed for %s: %s", machine.name, exc)
            return {"ok": False, "error": str(exc)}

    return await _check_machine_readiness(machine_id)


@celery_app.task(
    name="app.tasks.jobs.fix_root_readiness",
    time_limit=get_settings().ssh_connect_timeout + 60,
)
def fix_root_readiness(machine_id: str) -> dict[str, Any]:
    return asyncio.run(_fix_root_readiness(machine_id))


async def _refresh_all_machine_readiness() -> None:
    """Periodic sweep re-running the post-onboarding readiness check
    (`app.ssh.readiness`) for every machine with a pinned host key — same
    fan-out pattern and cadence (`FACTS_REFRESH_INTERVAL_SECONDS`) as
    `_refresh_all_machine_services`.

    Before this existed, `check_machine_readiness` only ever ran once,
    right after a host key was first trusted (or on an explicit "Re-check"/
    "Run initial setup" click) — so `Machine.readiness_missing` could go
    stale forever: ncurses-term or a sudoers grant removed by a later
    `apt-get autoremove` or a hand-edited sudoers file would never be
    reflected in the Overview banner unless someone happened to click
    "Re-check" again. This closes that gap the same way facts/packages/
    services already avoid it — a periodic sweep, not just an on-demand
    action.
    """
    async with db_session.AsyncSessionLocal() as session:
        result = await session.execute(
            select(Machine.id).where(Machine.is_active, Machine.host_key_fingerprint.is_not(None))
        )
        machine_ids = [row[0] for row in result.all()]

    for machine_id in machine_ids:
        check_machine_readiness.delay(str(machine_id))


@celery_app.task(name="app.tasks.jobs.refresh_all_machine_readiness")
def refresh_all_machine_readiness() -> None:
    asyncio.run(_refresh_all_machine_readiness())


def _due_machines[M](
    machines: list[M],
    *,
    last_checked_at: Callable[[M], datetime | None],
    override_seconds: Callable[[M], int | None],
    global_default_seconds: int,
    now: datetime,
) -> list[M]:
    """Filters a sweep's candidate machines down to the ones actually due,
    honoring each machine's own interval override (see `Machine.
    reachability_check_interval_seconds`/`facts_refresh_interval_seconds`)
    on top of the sweep's fixed Celery Beat tick rate. A machine never
    checked yet is always due.

    Generic over `_M` (rather than fixed to `Machine`) purely so
    `tests/test_due_machines.py` can exercise the interval math against a
    plain dataclass, no DB/ORM involved."""
    due: list[M] = []
    for machine in machines:
        last = last_checked_at(machine)
        if last is None:
            due.append(machine)
            continue
        effective_seconds = override_seconds(machine) or global_default_seconds
        if (now - last).total_seconds() >= effective_seconds:
            due.append(machine)
    return due


async def _ping_all_machines() -> None:
    """Cheap reachability sweep (TCP connect only, no auth) for the status
    badge shown in the UI, and — appending one `MachineReachabilitySample`
    row per machine actually checked — the Monitoring tab's "Availability"
    history. No new probe: this is the exact same check that already ran
    every tick to update `Machine.is_reachable`, just also kept instead of
    only ever overwriting those two columns with the latest value. Cadence
    is owned by Celery Beat (`REACHABILITY_CHECK_INTERVAL_SECONDS`, see
    `app.tasks.celery_app`), and a machine may additionally raise its own
    interval (never lower it below the tick rate) via
    `Machine.reachability_check_interval_seconds` — this job does the
    sweep, minus whichever machines aren't due yet, and returns."""
    async with db_session.AsyncSessionLocal() as session:
        result = await session.execute(select(Machine).where(Machine.is_active))
        machines = _due_machines(
            list(result.scalars().all()),
            last_checked_at=lambda m: m.last_ping_at,
            override_seconds=lambda m: m.reachability_check_interval_seconds,
            global_default_seconds=get_settings().reachability_check_interval_seconds,
            now=datetime.now(UTC),
        )
        if machines:
            # Configurable (REACHABILITY_CHECK_CONCURRENCY) — see that
            # setting's own docstring for how this interacts with a large
            # fleet and the sweep interval.
            semaphore = asyncio.Semaphore(get_settings().reachability_check_concurrency)

            async def _check(machine: Machine) -> tuple[Machine, ReachabilityResult]:
                async with semaphore:
                    outcome = await check_reachable(machine.ip_address, machine.port)
                    return machine, outcome

            results = await asyncio.gather(*(_check(m) for m in machines))

            now = datetime.now(UTC)
            transitions: list[tuple[Machine, bool]] = []
            for machine, outcome in results:
                was_reachable = machine.is_reachable
                # `None` means this machine has never been checked before —
                # not a transition from a known state, so nothing to notify.
                if was_reachable is not None and was_reachable != outcome.reachable:
                    transitions.append((machine, outcome.reachable))
                machine.is_reachable = outcome.reachable
                machine.last_ping_at = now
                session.add(
                    MachineReachabilitySample(
                        machine_id=machine.id,
                        checked_at=now,
                        reachable=outcome.reachable,
                        latency_ms=outcome.latency_ms,
                    )
                )
            await session.commit()
            for machine, _outcome in results:
                await publish_machine_event(str(machine.id), KIND_STATUS)
            # Notify only on an actual state change — not every tick that
            # simply confirms "still unreachable"/"still reachable" — see
            # app.services.notifications's module docstring.
            for machine, now_reachable in transitions:
                await notify(
                    session,
                    NotificationEventType.MACHINE_REACHABLE_AGAIN
                    if now_reachable
                    else NotificationEventType.MACHINE_UNREACHABLE,
                    machine=machine,
                )


@celery_app.task(name="app.tasks.jobs.ping_all_machines")
def ping_all_machines() -> None:
    asyncio.run(_ping_all_machines())


async def _check_machine_reachability_now(machine_id: str) -> dict[str, Any]:
    """The single-machine equivalent of `_ping_all_machines` — same TCP
    connect check, same `MachineReachabilitySample` history row, same
    `Machine.is_reachable`/`last_ping_at` update, just for one machine
    right now rather than every machine that happens to be due. Backs the
    Monitoring tab's "Refresh now" button (`app.web.routes.machines.
    refresh_machine_monitoring_endpoint`), run alongside
    `sample_machine_monitoring` so one click refreshes both of that tab's
    history sources instead of only the CPU/RAM/disk/services one."""
    async with db_session.AsyncSessionLocal() as session:
        machine = await session.get(Machine, uuid.UUID(machine_id))
        if machine is None:
            return {"ok": False, "error": "Machine not found."}

        outcome = await check_reachable(machine.ip_address, machine.port)
        now = datetime.now(UTC)
        was_reachable = machine.is_reachable
        machine.is_reachable = outcome.reachable
        machine.last_ping_at = now
        session.add(
            MachineReachabilitySample(
                machine_id=machine.id,
                checked_at=now,
                reachable=outcome.reachable,
                latency_ms=outcome.latency_ms,
            )
        )
        await session.commit()
        await publish_machine_event(str(machine.id), KIND_STATUS)
        # `was_reachable is None` means this is the machine's very first
        # reachability check ever — not a transition from a known state, so
        # nothing to notify about yet.
        if was_reachable is not None and was_reachable != outcome.reachable:
            await notify(
                session,
                NotificationEventType.MACHINE_REACHABLE_AGAIN
                if outcome.reachable
                else NotificationEventType.MACHINE_UNREACHABLE,
                machine=machine,
            )
        return {"ok": True, "reachable": outcome.reachable}


@celery_app.task(
    name="app.tasks.jobs.check_machine_reachability_now",
    time_limit=get_settings().ssh_connect_timeout + 15,
)
def check_machine_reachability_now(machine_id: str) -> dict[str, Any]:
    return asyncio.run(_check_machine_reachability_now(machine_id))


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
        machine.os_id = facts["os_id"]
        machine.kernel_version = facts["kernel_version"]
        machine.cpu_architecture = facts["cpu_architecture"]
        machine.cpu_cores = facts["cpu_cores"]
        machine.cpu_model = facts["cpu_model"]
        machine.ram_bytes = facts["ram_bytes"]
        machine.ram_speed_mhz = facts["ram_speed_mhz"]
        machine.disks = facts["disks"]
        machine.reboot_required = facts["reboot_required"]
        machine.uptime_seconds = facts["uptime_seconds"]
        machine.process_count = facts["process_count"]
        machine.filesystems = facts["filesystems"]
        machine.network_interfaces = facts["network_interfaces"]
        machine.facts_updated_at = datetime.now(UTC)
        await session.commit()
        await publish_machine_event(machine_id, KIND_FACTS)

        return {"ok": True}


@celery_app.task(name="app.tasks.jobs.refresh_machine_facts")
def refresh_machine_facts(machine_id: str) -> dict[str, Any]:
    return asyncio.run(_refresh_machine_facts(machine_id))


async def _refresh_all_machine_facts() -> None:
    """Periodic sweep scheduling a facts refresh for every machine with a
    pinned host key. Its cadence (`FACTS_REFRESH_INTERVAL_SECONDS`) is owned
    by Celery Beat — see `app.tasks.celery_app` — and a machine may raise
    its own interval via `Machine.facts_refresh_interval_seconds` (see
    `_due_machines`).

    This only *enqueues* per-machine tasks rather than awaiting them inline,
    so a slow or unreachable machine can't make this sweep itself run long
    enough to hit the default task time limit — each `refresh_machine_facts`
    task gets its own budget instead.
    """
    async with db_session.AsyncSessionLocal() as session:
        result = await session.execute(
            select(Machine).where(Machine.is_active, Machine.host_key_fingerprint.is_not(None))
        )
        machines = _due_machines(
            list(result.scalars().all()),
            last_checked_at=lambda m: m.facts_updated_at,
            override_seconds=lambda m: m.facts_refresh_interval_seconds,
            global_default_seconds=get_settings().facts_refresh_interval_seconds,
            now=datetime.now(UTC),
        )
        machine_ids = [m.id for m in machines]

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
        await publish_machine_event(machine_id, KIND_PACKAGES)

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


async def _refresh_machine_services(machine_id: str) -> dict[str, Any]:
    """Connect to one machine and refresh its systemd service-unit
    snapshot. Requires a pinned host key — machines without one are
    skipped. Same delete-then-bulk-insert replace as
    `_refresh_machine_packages`, and the same reasoning: a snapshot of
    "what's running right now," not a history of state changes."""
    settings = get_settings()

    async with db_session.AsyncSessionLocal() as session:
        machine = await session.get(Machine, uuid.UUID(machine_id))
        if machine is None:
            return {"ok": False, "error": "Machine not found."}
        if not machine.host_key_fingerprint:
            return {"ok": False, "error": "No pinned host key fingerprint yet."}

        secret = await resolve_machine_credential(machine, session)

        try:
            services = await gather_services(machine, secret, settings.ssh_connect_timeout)
        except SSHConnectionError as exc:
            logger.warning("refresh_machine_services failed for %s: %s", machine.name, exc)
            return {"ok": False, "error": str(exc)}

        await session.execute(
            delete(MachineService).where(MachineService.machine_id == machine.id)
        )
        session.add_all(
            MachineService(
                machine_id=machine.id,
                unit=entry["unit"][:255],
                load_state=entry["load_state"][:32],
                active_state=entry["active_state"][:32],
                sub_state=entry["sub_state"][:32],
                description=entry["description"][:500],
            )
            for entry in services
        )
        machine.services_updated_at = datetime.now(UTC)
        await session.commit()
        await publish_machine_event(machine_id, KIND_SERVICES)

        return {"ok": True, "service_count": len(services)}


@celery_app.task(name="app.tasks.jobs.refresh_machine_services")
def refresh_machine_services(machine_id: str) -> dict[str, Any]:
    return asyncio.run(_refresh_machine_services(machine_id))


async def _refresh_all_machine_services() -> None:
    """Periodic sweep scheduling a service-list refresh for every machine
    with a pinned host key — same fan-out pattern and cadence
    (`FACTS_REFRESH_INTERVAL_SECONDS`) as `_refresh_all_machine_packages`."""
    async with db_session.AsyncSessionLocal() as session:
        result = await session.execute(
            select(Machine.id).where(Machine.is_active, Machine.host_key_fingerprint.is_not(None))
        )
        machine_ids = [row[0] for row in result.all()]

    for machine_id in machine_ids:
        refresh_machine_services.delay(str(machine_id))


async def _sample_machine_monitoring(machine_id: str) -> dict[str, Any]:
    """Connect to one machine and take one CPU/RAM/disk/failed-services
    sample for the Monitoring tab. Requires a pinned host key — machines
    without one are skipped. Unlike facts/packages/services, this *appends*
    a new row rather than replacing a snapshot — it's a history, purged
    separately by `purge_old_monitoring_samples`."""
    settings = get_settings()

    async with db_session.AsyncSessionLocal() as session:
        machine = await session.get(Machine, uuid.UUID(machine_id))
        if machine is None:
            return {"ok": False, "error": "Machine not found."}
        if not machine.host_key_fingerprint:
            return {"ok": False, "error": "No pinned host key fingerprint yet."}

        secret = await resolve_machine_credential(machine, session)

        try:
            sample = await gather_monitoring_sample(
                machine, secret, settings.ssh_connect_timeout
            )
        except SSHConnectionError as exc:
            logger.warning("sample_machine_monitoring failed for %s: %s", machine.name, exc)
            return {"ok": False, "error": str(exc)}

        now = datetime.now(UTC)
        session.add(
            MachineMonitoringSample(
                machine_id=machine.id,
                sampled_at=now,
                cpu_percent=sample["cpu_percent"],
                load1=sample["load1"],
                load5=sample["load5"],
                load15=sample["load15"],
                ram_used_bytes=sample["ram_used_bytes"],
                ram_total_bytes=sample["ram_total_bytes"],
                network_io=sample["network_io"],
                disk_io=sample["disk_io"],
                filesystems=sample["filesystems"],
                failed_services_count=sample["failed_services_count"],
            )
        )
        machine.monitoring_updated_at = now
        await session.commit()

        return {"ok": True}


@celery_app.task(
    name="app.tasks.jobs.sample_machine_monitoring",
    # The `sleep 1` baked into MONITORING_COMMAND plus normal SSH connect
    # overhead — comfortably under a minute even for a slow/distant host.
    time_limit=get_settings().ssh_connect_timeout + 30,
)
def sample_machine_monitoring(machine_id: str) -> dict[str, Any]:
    return asyncio.run(_sample_machine_monitoring(machine_id))


async def _monitor_all_machines() -> None:
    """Periodic sweep scheduling a monitoring sample for every machine with
    a pinned host key, minus whichever aren't due yet under their own
    `Machine.monitoring_interval_seconds` override (see `_due_machines`) —
    same fan-out-only pattern as the other sweeps, cadence owned by Celery
    Beat (`MONITORING_INTERVAL_SECONDS`)."""
    async with db_session.AsyncSessionLocal() as session:
        result = await session.execute(
            select(Machine).where(Machine.is_active, Machine.host_key_fingerprint.is_not(None))
        )
        machines = _due_machines(
            list(result.scalars().all()),
            last_checked_at=lambda m: m.monitoring_updated_at,
            override_seconds=lambda m: m.monitoring_interval_seconds,
            global_default_seconds=get_settings().monitoring_interval_seconds,
            now=datetime.now(UTC),
        )
        machine_ids = [m.id for m in machines]

    for machine_id in machine_ids:
        sample_machine_monitoring.delay(str(machine_id))


@celery_app.task(name="app.tasks.jobs.monitor_all_machines")
def monitor_all_machines() -> None:
    asyncio.run(_monitor_all_machines())


_MONITORING_SAMPLE_PURGE_ACTOR = "retention policy (automatic)"


async def _purge_old_monitoring_samples() -> None:
    """Delete `MachineMonitoringSample` **and** `MachineReachabilitySample`
    rows older than each machine's effective retention —
    `Machine.monitoring_history_retention_days` if set, else
    `AppSettings.monitoring_history_retention_days` (`None` on both = keep
    that machine's samples forever). One retention setting covers both
    tables — they're the same "how long does this fleet's own history
    stick around" question, not two knobs to configure. One `DELETE` per
    machine per table rather than a single global cutoff (unlike
    `_purge_old_machine_update_runs`) since retention can differ per
    machine — acceptable for a once-a-day job; see
    wiki/Host-Requirements.md if this ever needs to scale further."""
    async with db_session.AsyncSessionLocal() as session:
        app_settings = await get_or_create_app_settings(session)
        default_retention_days = app_settings.monitoring_history_retention_days

        result = await session.execute(
            select(Machine.id, Machine.monitoring_history_retention_days)
        )
        rows = result.all()

        now = datetime.now(UTC)
        total_deleted = 0
        for machine_id, override_days in rows:
            retention_days = override_days or default_retention_days
            if not retention_days:
                continue
            cutoff = now - timedelta(days=retention_days)

            monitoring_filter = (
                MachineMonitoringSample.machine_id == machine_id,
                MachineMonitoringSample.sampled_at < cutoff,
            )
            count_result = await session.execute(
                select(func.count()).select_from(MachineMonitoringSample).where(*monitoring_filter)
            )
            machine_deleted = count_result.scalar_one()
            if machine_deleted:
                await session.execute(delete(MachineMonitoringSample).where(*monitoring_filter))
                total_deleted += machine_deleted

            reachability_filter = (
                MachineReachabilitySample.machine_id == machine_id,
                MachineReachabilitySample.checked_at < cutoff,
            )
            count_result = await session.execute(
                select(func.count())
                .select_from(MachineReachabilitySample)
                .where(*reachability_filter)
            )
            reachability_deleted = count_result.scalar_one()
            if reachability_deleted:
                await session.execute(
                    delete(MachineReachabilitySample).where(*reachability_filter)
                )
                total_deleted += reachability_deleted

        if not total_deleted:
            return

        await session.commit()

        await log_event(
            session,
            actor=_MONITORING_SAMPLE_PURGE_ACTOR,
            action="monitoring_samples.purge",
            summary=(
                f"Purged {total_deleted} monitoring sample"
                f"{'s' if total_deleted != 1 else ''} past their machine's retention window"
            ),
            details={"deleted_count": total_deleted},
        )


@celery_app.task(name="app.tasks.jobs.purge_old_monitoring_samples")
def purge_old_monitoring_samples() -> None:
    asyncio.run(_purge_old_monitoring_samples())


@celery_app.task(name="app.tasks.jobs.refresh_all_machine_packages")
def refresh_all_machine_packages() -> None:
    asyncio.run(_refresh_all_machine_packages())


@celery_app.task(name="app.tasks.jobs.refresh_all_machine_services")
def refresh_all_machine_services() -> None:
    asyncio.run(_refresh_all_machine_services())


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

        # Captured before the upgrade itself starts — the "before" picture
        # "Roll back this update" (`_rollback_machine_update` below) later
        # diffs against. A failure here (unreachable machine, timeout) is
        # logged and never fails the update run itself — it only means
        # rollback won't be offered for this particular run, same as a run
        # from before this feature existed.
        try:
            snapshot = await capture_package_snapshot(machine, secret, settings.ssh_connect_timeout)
            run.package_snapshot = json.dumps(snapshot)
        except (SSHConnectionError, TimeoutError) as exc:
            logger.warning(
                "Package snapshot capture failed for %s before update run %s: %s",
                machine.name,
                run.id,
                exc,
            )

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

        if run.status == UpdateRunStatus.FAILED:
            await notify(
                session,
                NotificationEventType.UPDATE_RUN_FAILED,
                machine=machine,
                context={"details": run.error or ""},
            )

    refresh_machine_packages.delay(str(run.machine_id))
    check_machine_updates.delay(str(run.machine_id))


@celery_app.task(
    name="app.tasks.jobs.run_machine_update",
    time_limit=get_settings().update_timeout_seconds,
)
def run_machine_update(run_id: str) -> None:
    asyncio.run(_run_machine_update(run_id))


async def _rollback_machine_update(run_id: str) -> None:
    """Execute one rollback `MachineUpdateRun` (`rollback_of_run_id` set) —
    re-install every package whose version changed since the source run's
    `package_snapshot`, back to exactly what it was. See
    `app.ssh.updates.build_rollback_command` for the caveat this depends
    on (the old `.deb` still being resolvable from a configured apt
    source) and `app/web/routes/machines.py`'s `rollback_machine_update_endpoint`
    for how this run gets created.

    Diffs against a **freshly captured** current snapshot rather than
    blindly replaying every package in the source snapshot — only
    packages whose version actually differs are touched, so a rollback
    run days later doesn't also revert something *else* that was updated
    in the meantime for unrelated reasons, and a rollback with nothing
    left to undo (e.g. run twice) is a fast no-op instead of a full apt
    invocation."""
    settings = get_settings()

    async with db_session.AsyncSessionLocal() as session:
        run = await session.get(MachineUpdateRun, uuid.UUID(run_id))
        if run is None:
            return

        machine = await session.get(Machine, run.machine_id)
        source_run = (
            await session.get(MachineUpdateRun, run.rollback_of_run_id)
            if run.rollback_of_run_id
            else None
        )
        if machine is None or source_run is None or not source_run.package_snapshot:
            run.status = UpdateRunStatus.FAILED
            run.error = "The source update run's package snapshot is no longer available."
            run.finished_at = datetime.now(UTC)
            await session.commit()
            return

        run.status = UpdateRunStatus.RUNNING
        run.started_at = datetime.now(UTC)
        await session.commit()

        secret = await resolve_machine_credential(machine, session)

        try:
            snapshot: dict[str, str] = json.loads(source_run.package_snapshot)
            current = await capture_package_snapshot(machine, secret, settings.ssh_connect_timeout)
            target_versions = {
                package: version
                for package, version in snapshot.items()
                if package in current and current[package] != version
            }
            if not target_versions:
                run.output = (
                    "Nothing to roll back — every snapshotted package's installed version "
                    "already matches the pre-update snapshot."
                )
                run.status = UpdateRunStatus.SUCCEEDED
            else:
                result = await run_rollback(
                    machine,
                    secret,
                    target_versions,
                    settings.ssh_connect_timeout,
                    settings.update_timeout_seconds,
                )
                run.output = _truncate_output(result.output)
                if result.exit_status == 0:
                    run.status = UpdateRunStatus.SUCCEEDED
                else:
                    run.status = UpdateRunStatus.FAILED
                    run.error = f"apt exited with status {result.exit_status}."
        except (SSHConnectionError, TimeoutError) as exc:
            logger.warning("rollback_machine_update failed for %s: %s", machine.name, exc)
            run.status = UpdateRunStatus.FAILED
            run.error = str(exc)

        run.finished_at = datetime.now(UTC)
        await session.commit()

    refresh_machine_packages.delay(str(run.machine_id))
    check_machine_updates.delay(str(run.machine_id))


@celery_app.task(
    name="app.tasks.jobs.rollback_machine_update",
    time_limit=get_settings().update_timeout_seconds,
)
def rollback_machine_update(run_id: str) -> None:
    asyncio.run(_rollback_machine_update(run_id))


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
            await publish_machine_event(machine_id, KIND_UPDATES)
            return {"ok": True}

        # `apt-get update` itself failed (commonly: no passwordless sudo
        # configured for this machine yet) — record that we tried and when,
        # but leave the apt counts/list as "unknown" rather than implying 0
        # updates.
        machine.upgradable_count = None
        machine.security_upgradable_count = None
        machine.apt_upgradable_packages = None
        await session.commit()
        await publish_machine_event(machine_id, KIND_UPDATES)
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


_MACHINE_UPDATE_RUN_PURGE_ACTOR = "retention policy (automatic)"


async def _purge_old_machine_update_runs() -> None:
    """Delete `MachineUpdateRun` rows older than `AppSettings.
    machine_update_run_retention_days` — same shape as
    `_purge_old_fleet_snapshots` above, including being skipped entirely
    when retention is unset (`None` = keep forever). Only the stored run
    record/output is purged; the `machine.updates.run` audit log entry
    recorded when the update was originally triggered is a separate table
    with its own (also configurable) retention and is unaffected."""
    async with db_session.AsyncSessionLocal() as session:
        app_settings = await get_or_create_app_settings(session)
        retention_days = app_settings.machine_update_run_retention_days
        if not retention_days:
            return

        cutoff = datetime.now(UTC) - timedelta(days=retention_days)
        count_result = await session.execute(
            select(func.count())
            .select_from(MachineUpdateRun)
            .where(MachineUpdateRun.created_at < cutoff)
        )
        deleted_count = count_result.scalar_one()
        if not deleted_count:
            return

        await session.execute(
            delete(MachineUpdateRun).where(MachineUpdateRun.created_at < cutoff)
        )
        await session.commit()

        await log_event(
            session,
            actor=_MACHINE_UPDATE_RUN_PURGE_ACTOR,
            action="machine_update_runs.purge",
            summary=(
                f"Purged {deleted_count} update run record"
                f"{'s' if deleted_count != 1 else ''} older than {retention_days} day(s)"
            ),
            details={"deleted_count": deleted_count, "retention_days": retention_days},
        )


@celery_app.task(name="app.tasks.jobs.purge_old_machine_update_runs")
def purge_old_machine_update_runs() -> None:
    asyncio.run(_purge_old_machine_update_runs())
