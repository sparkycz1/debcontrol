"""Background jobs processed by arq (queue in Redis)."""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select

from app.core.config import get_settings
from app.db.models.machine import Machine
from app.db.session import AsyncSessionLocal
from app.ssh.client import test_connection
from app.ssh.credentials import resolve_machine_credential
from app.ssh.exceptions import SSHConnectionError
from app.ssh.facts import gather_facts
from app.ssh.reachability import check_reachable

logger = logging.getLogger(__name__)

# Cap how many machines are checked/refreshed at once so one slow/firewalled
# host can't make a sweep over the whole fleet take forever.
_REACHABILITY_CONCURRENCY = 20


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
