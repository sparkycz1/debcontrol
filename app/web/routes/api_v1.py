"""REST API for machines, machine groups, and bulk/fleet-wide actions — for
external scripts/monitoring, authenticated with a per-user API token
(`app.auth.dependencies.require_api_permission`), not a browser session.

Lives under `/api/`, already on `app.auth.middleware`'s public-prefix
allowlist — same reasoning as `POST /api/inform`: a machine-to-machine
surface with its own bearer-token authentication, not a cookie-based one.

Every mutating/action endpoint here calls into the exact same service
functions the equivalent web route uses (`app.services.machine_actions`,
`app.ssh.updates`, ...) and requires the exact same `Permission` the web
route does — this is a second door into the same house, not a looser one.
Destructive actions that the web UI gates behind a typed confirmation
phrase require an explicit `confirm` field here instead (see each route's
docstring).

What's deliberately still web-UI-only, and why: SSH key rotation
(`/settings/ssh-key/...`), LDAP/OIDC configuration, syslog forwarding,
the AI assistant's provider credentials and the whole-application restore
(`api_v1_backup.py` only makes the backup) are excluded for the reasons given
in wiki/Architecture's "The REST API: read and write, mirroring the web
UI" section — each one is either a secret/credential surface or carries a
lock-out/blast-radius risk that's meant to be handled deliberately, by a
human, not scriptable. (Notifications, endpoint checks, and the
operational part of Settings have their own routers —
`api_v1_notifications.py`, `api_v1_checks.py`, `api_v1_settings.py`.)
The interactive SSH terminal
(`app/web/routes/terminal_ws.py`, and likewise the Logs tab's live-follow
stream in `logs_ws.py`) and the AI assistant's chat
(`app/web/routes/ai.py`) are excluded for a different reason: both are
inherently interactive, browser-only features (a live WebSocket relaying
keystrokes to a PTY and a real terminal emulator's output back; a
conversational back-and-forth where every proposed action needs an
explicit human confirmation click) with no meaningful "REST" shape to
expose — there's nothing here for a script to call that would do anything
useful without a human driving it. Impersonate (`/users/{id}/impersonate`,
`app/web/routes/impersonation.py`) is excluded for the same reason as the
terminal/AI chat: it swaps the browser's own session cookie for another
one, a concept that doesn't translate to a stateless bearer-token API call
at all — an API token already scopes to one fixed account (see
`app.auth.api_tokens`) by design. `POST /{id}/run-onboarding-with-
credential` (a *fresh*, one-time password submitted through the "Fix it"
flow, not the machine's stored credential) is excluded for the same
secret-handling reason as SSH key rotation; `POST /{id}/run-onboarding`
(using the credential already on file) has an API equivalent below. CSV
bulk import of pending machines is excluded too — a script importing
machines already has `POST /machines` (or `POST /api/inform` for genuine
self-registration) and doesn't need a CSV-parsing endpoint of its own.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
import uuid
from dataclasses import asdict
from datetime import UTC, datetime

# NOT the builtin `TimeoutError` — `celery.exceptions.TimeoutError` does not
# subclass it, so catching the builtin around `AsyncResult.get(timeout=...)`
# would silently never match.
from celery.exceptions import TimeoutError as CeleryTimeoutError
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.audit import log_event
from app.auth.dependencies import get_api_token_user, require_api_permission
from app.core.app_settings import get_or_create_app_settings
from app.core.config import get_settings
from app.core.security import encrypt_secret
from app.db.models.audit_log import AuditOutcome
from app.db.models.machine import AuthMethod, Machine
from app.db.models.machine_group import MachineGroup
from app.db.models.machine_monitoring_sample import MachineMonitoringSample
from app.db.models.machine_note import MAX_NOTE_LENGTH
from app.db.models.machine_package import MachinePackage
from app.db.models.machine_service import MachineService
from app.db.models.machine_update_run import MachineUpdateRun, UpdateRunStatus, UpgradeStrategy
from app.db.models.pending_machine import PendingMachine
from app.db.models.role import Permission
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.acknowledgement import AcknowledgeRequest
from app.schemas.machine import MachineCreate, MachineUpdate
from app.schemas.machine_config import MachineConfigExport
from app.schemas.machine_group import MachineGroupCreate
from app.services import acknowledgements, machine_timeline, monitoring_history
from app.services.access_scope import (
    can_see_group_id,
    can_see_machine,
    groups_visible_to,
    is_restricted,
    machines_visible_to,
    visible_machines_by_ids,
)
from app.services.fleet_overview import build_fleet_overview
from app.services.machine_actions import (
    send_power_to_machines,
    trigger_check_updates,
    trigger_updates,
)
from app.services.machine_config import export_machine_config, import_machine_config
from app.services.machine_grouping import assign_machines_to_group
from app.services.machine_notes import EmptyNoteError, add_note, delete_note
from app.services.machine_tags import (
    add_tags_to_machines,
    normalize_tag_names,
    remove_tags_from_machines,
    set_machine_tags,
)
from app.services.security_updates import load_security_overview
from app.ssh import logs as ssh_logs
from app.ssh import proxmox
from app.ssh.client import discover_host_key_fingerprint
from app.ssh.containers import CONTAINER_ACTIONS
from app.ssh.exceptions import SSHConnectionError
from app.ssh.logs import is_container_name_valid
from app.ssh.packages import PackageSource
from app.ssh.power import PowerAction
from app.ssh.security_advisories import is_safe_package_name
from app.tasks import jobs as tasks
from app.tasks.jobs import (
    preview_machine_update,
    rollback_machine_update,
    run_machine_update,
    send_machine_power_command,
)
from app.web.machine_search import apply_group_filter, apply_status_filter, apply_tag_filter

router = APIRouter(prefix="/api/v1")

_view_machines = Depends(require_api_permission(Permission.MACHINE_VIEW))
_manage_machines = Depends(require_api_permission(Permission.MACHINE_MANAGE))
_action_terminal = Depends(require_api_permission(Permission.ACTION_TERMINAL))
_view_groups = Depends(require_api_permission(Permission.GROUP_VIEW))
_manage_groups = Depends(require_api_permission(Permission.GROUP_MANAGE))
_action_updates = Depends(require_api_permission(Permission.ACTION_UPDATES))
_action_power = Depends(require_api_permission(Permission.ACTION_POWER))

# Fingerprint shaped like "SHA256:<base64...>", as returned by AsyncSSH/OpenSSH
# — same pattern the web UI's trust-host-key form validates against.
_FINGERPRINT_RE = re.compile(r"^[A-Za-z0-9]+:[A-Za-z0-9+/=_-]+$")

_PACKAGE_SEARCH_LIMIT = 500
_UPDATE_RUNS_PAGE_SIZE = 50

# Fixed confirmation values an API client must echo back for a destructive
# action — the API equivalent of the web UI's typed-name confirmation page.
# "SELECTED MACHINES"/"ALL MACHINES" mirror the phrases the web UI itself
# uses for the same ad-hoc-selection / "All machines" cases.
_BULK_POWER_CONFIRM_PHRASE = "SELECTED MACHINES"
_ALL_MACHINES_CONFIRM_PHRASE = "ALL MACHINES"


def _as_utc(value: datetime | None) -> datetime | None:
    """A query-string timestamp without an offset is read as UTC."""
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _isoformat(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _machine_to_dict(machine: Machine) -> dict[str, object]:
    return {
        "id": str(machine.id),
        "name": machine.name,
        "ip_address": machine.ip_address,
        "port": machine.port,
        "username": machine.username,
        "auth_method": machine.auth_method.value,
        "group": machine.group.name if machine.group else None,
        "group_id": str(machine.group_id) if machine.group_id else None,
        "description": machine.description,
        "runbook": machine.runbook,
        "tags": [tag.name for tag in machine.tags],
        "is_active": machine.is_active,
        "is_reachable": machine.is_reachable,
        "last_ping_at": _isoformat(machine.last_ping_at),
        "acknowledgement": acknowledgements.as_dict(machine),
        "host_key_fingerprint": machine.host_key_fingerprint,
        "os_version": machine.os_version,
        "pve_version": machine.pve_version,
        "kernel_version": machine.kernel_version,
        "cpu_architecture": machine.cpu_architecture,
        "cpu_model": machine.cpu_model,
        "cpu_cores": machine.cpu_cores,
        "ram_bytes": machine.ram_bytes,
        "ram_speed_mhz": machine.ram_speed_mhz,
        "uptime_seconds": machine.uptime_seconds,
        "process_count": machine.process_count,
        "reboot_required": machine.reboot_required,
        "upgradable_count": machine.upgradable_count,
        "security_upgradable_count": machine.security_upgradable_count,
        "flatpak_upgradable_count": machine.flatpak_upgradable_count,
        "snap_upgradable_count": machine.snap_upgradable_count,
        "apt_upgradable_packages": machine.apt_upgradable_packages,
        "apt_held_packages": machine.apt_held_packages,
        "flatpak_upgradable_packages": machine.flatpak_upgradable_packages,
        "snap_upgradable_packages": machine.snap_upgradable_packages,
        "updates_checked_at": _isoformat(machine.updates_checked_at),
        "packages_updated_at": _isoformat(machine.packages_updated_at),
    }


def _group_to_dict(group: MachineGroup) -> dict[str, object]:
    return {
        "id": str(group.id),
        "name": group.name,
        "description": group.description,
        "machine_count": len(group.machines),
    }


def _package_to_dict(pkg: MachinePackage, *, include_machine: bool = False) -> dict[str, object]:
    data: dict[str, object] = {
        "id": str(pkg.id),
        "machine_id": str(pkg.machine_id),
        "source": pkg.source.value,
        "name": pkg.name,
        "version": pkg.version,
        "held": pkg.held,
    }
    if include_machine:
        data["machine_name"] = pkg.machine.name if pkg.machine else None
    return data


def _update_run_to_dict(run: MachineUpdateRun) -> dict[str, object]:
    return {
        "id": str(run.id),
        "machine_id": str(run.machine_id),
        "batch_id": str(run.batch_id) if run.batch_id else None,
        "strategy": run.strategy.value,
        "status": run.status.value,
        "output": run.output,
        "error": run.error,
        # Not the raw snapshot (a full package list per run is a lot to hand
        # back for something most callers only need as a yes/no) — just
        # whether "Roll back this update" is available for this run.
        "has_package_snapshot": run.package_snapshot is not None,
        "rollback_of_run_id": str(run.rollback_of_run_id) if run.rollback_of_run_id else None,
        "started_at": _isoformat(run.started_at),
        "finished_at": _isoformat(run.finished_at),
        "created_at": _isoformat(run.created_at),
    }


async def _get_machine_or_404(machine_id: uuid.UUID, db: AsyncSession, user: User) -> Machine:
    """Scoped exactly like the web UI's equivalent helper — a token whose
    account is restricted to specific machine groups gets a 404, not a 403
    and certainly not the data, for anything outside them. This API is "a
    second door into the same house, not a looser one" (see the module
    docstring), and that applies to visibility scoping too."""
    query = await machines_visible_to(db, user)
    result = await db.execute(
        query.options(selectinload(Machine.group))
        .where(Machine.id == machine_id)
        # A route that waited for a background job reloads the machine to
        # show what the job wrote — without this the session would hand back
        # the object it already holds, with the values from before the job.
        .execution_options(populate_existing=True)
    )
    machine = result.scalar_one_or_none()
    if machine is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Machine not found.")
    return machine


async def _get_group_or_404(group_id: uuid.UUID, db: AsyncSession, user: User) -> MachineGroup:
    query = await groups_visible_to(db, user)
    result = await db.execute(
        query.options(selectinload(MachineGroup.machines)).where(MachineGroup.id == group_id)
    )
    group = result.scalar_one_or_none()
    if group is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found.")
    return group


async def _require_group_in_scope(
    db: AsyncSession, user: User, group_id: uuid.UUID | None
) -> None:
    """A restricted account may only file a machine into a group it can see
    — ungrouped included, since an ungrouped machine would be invisible to
    its own creator. A 403 rather than a 404: the caller submitted this
    group id itself, so there is nothing left to conceal."""
    if not await can_see_group_id(db, user, group_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail='"group_id" must name a machine group this account has access to.',
        )


async def _visible_machines(db: AsyncSession, user: User) -> list[Machine]:
    """Every machine this token's account can see — what "All machines"
    means for it. Same reasoning as the web UI's `_all_visible_machines`."""
    result = await db.execute(await machines_visible_to(db, user))
    return list(result.scalars().all())


# --- Machines: reads --------------------------------------------------------


@router.get("/machines", dependencies=[_view_machines])
async def list_machines_api(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
    tag: list[str] = Query(default=[]),
    tag_mode: str = "or",
    status_filter: str = Query("", alias="status"),
    group: str = "",
    limit: int | None = Query(None, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> list[dict[str, object]]:
    """Same filters as the Machines page: `tag` (repeatable, `tag_mode=and`
    to require all), `status` (online / offline / updates / security / reboot /
    changed / unconfirmed) and `group` (a group id, or `none`). Ordered by
    name; `limit` (max 1000) + `offset` page through a large fleet — without
    `limit`, every matching machine comes back at once, as before."""
    query = (await machines_visible_to(db, user)).options(selectinload(Machine.group))
    query = apply_tag_filter(query, tag, tag_mode if tag_mode == "and" else "or")
    query = apply_group_filter(apply_status_filter(query, status_filter), group)
    query = query.order_by(Machine.name, Machine.id).offset(offset)
    if limit is not None:
        query = query.limit(limit)
    result = await db.execute(query)
    return [_machine_to_dict(m) for m in result.scalars().all()]


@router.get("/fleet", dependencies=[_view_machines])
async def fleet_overview_api(
    db: AsyncSession = Depends(get_db), user: User = Depends(get_api_token_user)
) -> list[dict[str, object]]:
    """The Fleet page's cards as data — every visible, active machine with
    its latest CPU/RAM/disk/temperature/load/containers readings."""
    query = (await machines_visible_to(db, user)).where(Machine.is_active)
    result = await db.execute(query.order_by(Machine.name))
    rows = await build_fleet_overview(db, list(result.scalars().all()))
    return [row.as_dict() for row in rows]


@router.get("/machines/security-updates", dependencies=[_view_machines])
async def security_updates_api(
    db: AsyncSession = Depends(get_db), user: User = Depends(get_api_token_user)
) -> list[dict[str, object]]:
    """Machines → Security updates as data: every pending apt security
    update across the visible fleet, grouped by (package, new version),
    with `cves` (None = not looked up yet), `urgency` and the machines it's
    pending on — see `app.services.security_updates`."""
    rows = await load_security_overview(db, await machines_visible_to(db, user))
    return [row.as_dict() for row in rows]


@router.get("/machines/{machine_id}/proxmox", dependencies=[_view_machines])
async def machine_proxmox_api(
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    """A machine's Proxmox tab as data: the Proxmox VE version, VMs and
    containers with their state, ZFS pools, storages and backups (jobs,
    recent vzdump tasks, guests no job covers). Each is null on a machine
    without it — see `app.ssh.proxmox` for every field. Guests and pools
    are as of `monitoring_updated_at`, the rest as of `facts_updated_at`."""
    machine = await _get_machine_or_404(machine_id, db, user)
    return {
        "product": machine.proxmox_product,
        "pve_version": machine.pve_version,
        "cluster": machine.pve_cluster,
        "failed_tasks": machine.pve_failed_tasks,
        "pbs_version": machine.pbs_version,
        "backup_server": machine.pbs_data,
        "pmg_version": machine.pmg_version,
        "mail_gateway": machine.pmg_data,
        "guests": machine.pve_guests,
        "zfs_pools": machine.zfs_pools,
        "storage": machine.pve_storage,
        "backups": machine.pve_backups,
        "monitoring_updated_at": _isoformat(machine.monitoring_updated_at),
        "facts_updated_at": _isoformat(machine.facts_updated_at),
    }


@router.post(
    "/machines/{machine_id}/proxmox/guests/{vmid}/{action}", dependencies=[_action_power]
)
async def proxmox_guest_action_api(
    request: Request,
    machine_id: uuid.UUID,
    vmid: int,
    action: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    """Start / shutdown / reboot / stop one Proxmox VE guest (as listed in
    `GET .../proxmox` → `guests`). Same permission as machine power
    actions; audited as `machine.guest.<action>`."""
    machine = await _get_machine_or_404(machine_id, db, user)
    guest = proxmox.find_guest(machine.pve_guests, vmid)
    if action not in proxmox.GUEST_ACTIONS or guest is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Unknown guest or action."
        )
    app_settings = await get_or_create_app_settings(db)
    error: str | None = None
    try:
        result = await asyncio.to_thread(
            tasks.run_proxmox_guest_action.delay(str(machine.id), vmid, action).get,
            timeout=app_settings.ssh_connect_timeout + 90,
        )
        if isinstance(result, dict) and not result.get("ok"):
            error = str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        error = "The command did not finish in time."
    except Exception as exc:
        error = str(exc)
    await log_event(
        db,
        request=request,
        action=f"machine.guest.{action}",
        summary=f'Guest {vmid} {action} on "{machine.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"vmid": vmid, **({"error": error} if error else {})},
    )
    if error is not None:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=error)
    return {"vmid": vmid, "action": action, "ok": True}


@router.get("/machines/{machine_id}/timeline", dependencies=[_view_machines])
async def machine_timeline_api(
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
    days: int = machine_timeline.DEFAULT_RANGE_DAYS,
    kind: str = "",
) -> dict[str, object]:
    """A machine's History tab as data, newest first: notes, detected
    changes, update runs, reachability transitions and — only for a token
    whose user has `audit.view` — audited actions. `days` is one of
    1/7/30/90/365, `kind` optionally one of `note`/`change`/`update_run`/
    `reachability`/`audit`. See `app.services.machine_timeline`."""
    machine = await _get_machine_or_404(machine_id, db, user)
    timeline = await machine_timeline.load_timeline(
        db,
        machine,
        days=days,
        include_audit=user.has_permission(Permission.AUDIT_VIEW),
        kinds={kind} if kind in machine_timeline.TIMELINE_KINDS else None,
    )
    return {
        "days": timeline.days,
        "since": timeline.since.isoformat(),
        "truncated": timeline.truncated,
        "includes_audit": timeline.includes_audit,
        "events": [event.as_dict() for event in timeline.events],
    }


class MachineNoteCreate(BaseModel):
    body: str = Field(min_length=1, max_length=MAX_NOTE_LENGTH)


@router.post(
    "/machines/{machine_id}/notes",
    dependencies=[_manage_machines],
    status_code=status.HTTP_201_CREATED,
)
async def add_machine_note_api(
    machine_id: uuid.UUID,
    payload: MachineNoteCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    """Add a note to the machine's history — same as the History tab's
    form (`machine.manage`, audited as `machine.note.add`)."""
    machine = await _get_machine_or_404(machine_id, db, user)
    try:
        note = await add_note(db, request, machine, user, payload.body)
    except EmptyNoteError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="The note is empty."
        ) from None
    return {
        "id": str(note.id),
        "author": note.author,
        "body": note.body,
        "created_at": note.created_at.isoformat() if note.created_at else None,
    }


@router.delete(
    "/machines/{machine_id}/notes/{note_id}",
    dependencies=[_manage_machines],
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_machine_note_api(
    machine_id: uuid.UUID,
    note_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> None:
    machine = await _get_machine_or_404(machine_id, db, user)
    if not await delete_note(db, request, machine, note_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found.")


@router.get("/machines/package-search", dependencies=[_view_machines])
async def package_search_api(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
    q: str = "",
    pkg_source: str = "",
) -> dict[str, object]:
    """Fleet-wide package search — the API equivalent of `GET
    /machines/package-search`. See that route for the reasoning behind the
    500-row cap."""
    if not q.strip():
        return {"results": [], "truncated": False}
    visible_ids = (await machines_visible_to(db, user)).with_only_columns(Machine.id)
    query = (
        select(MachinePackage)
        .options(selectinload(MachinePackage.machine))
        .where(
            MachinePackage.name.ilike(f"%{q.strip()}%"),
            MachinePackage.machine_id.in_(visible_ids),
        )
    )
    if pkg_source in {source.value for source in PackageSource}:
        query = query.where(MachinePackage.source == PackageSource(pkg_source))
    query = query.order_by(MachinePackage.name).limit(_PACKAGE_SEARCH_LIMIT + 1)
    result = await db.execute(query)
    results = list(result.scalars().all())
    truncated = len(results) > _PACKAGE_SEARCH_LIMIT
    results = results[:_PACKAGE_SEARCH_LIMIT]
    return {
        "results": [_package_to_dict(p, include_machine=True) for p in results],
        "truncated": truncated,
    }


@router.get("/machines/config/export", dependencies=[_view_machines])
async def export_machine_config_api(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> MachineConfigExport:
    """The API equivalent of `GET /machines/config/export?format=json` — see
    `app.services.machine_config`'s module docstring for exactly what's
    included/excluded and why. No CSV variant here (the web UI's is a plain
    download link for a browser; a script consuming this API wants JSON)."""
    return await export_machine_config(db, user)


@router.post("/machines/config/import", dependencies=[_manage_machines])
async def import_machine_config_api(
    request: Request, payload: MachineConfigExport, db: AsyncSession = Depends(get_db)
) -> dict[str, object]:
    """The API equivalent of `POST /machines/config/import` — same
    conflict-handling/security policy, see `app.services.machine_config`."""
    result = await import_machine_config(db, payload)
    await log_event(
        db,
        request=request,
        action="machine.config_import",
        summary=result.summary(),
        details=result.to_dict(),
    )
    return result.to_dict()


# --- Pending machines (self-registration review queue) -----------------------
# Registered here, before `/machines/{machine_id}` below, so "pending" is
# never swallowed as an attempted (and invalid) machine UUID — FastAPI/
# Starlette matches path routes in registration order and commits to the
# first one whose shape fits, same reasoning as `/machines/package-search`
# and `/machines/config/export` above.


def _pending_machine_to_dict(pending: PendingMachine) -> dict[str, object]:
    return {
        "id": str(pending.id),
        "ip_address": pending.ip_address,
        "reported_hostname": pending.reported_hostname,
        "os_version": pending.os_version,
        "kernel_version": pending.kernel_version,
        "cpu_cores": pending.cpu_cores,
        "ram_bytes": pending.ram_bytes,
        "disks": pending.disks,
        "source_ip": pending.source_ip,
        "created_at": _isoformat(pending.created_at),
    }


@router.get("/machines/pending", dependencies=[_view_machines])
async def list_pending_machines_api(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> list[dict[str, object]]:
    """Machines that announced themselves via `POST /api/inform` and are
    awaiting review — see `app.db.models.pending_machine`'s module
    docstring. Not scoped by machine group: a pending entry isn't a real
    `Machine` yet, so there's nothing to scope against."""
    result = await db.execute(select(PendingMachine).order_by(PendingMachine.created_at.desc()))
    return [_pending_machine_to_dict(p) for p in result.scalars().all()]


@router.post("/machines/pending/{pending_id}/dismiss", dependencies=[_manage_machines])
async def dismiss_pending_machine_api(
    request: Request,
    pending_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> Response:
    pending = await db.get(PendingMachine, pending_id)
    if pending is not None:
        await db.delete(pending)
        await db.commit()
        await log_event(
            db,
            request=request,
            action="machine.pending.dismiss",
            summary=f'Dismissed pending machine "{pending.ip_address}"',
            target_type="pending_machine",
            target_id=pending_id,
            target_label=pending.ip_address,
        )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/machines/{machine_id}", dependencies=[_view_machines])
async def get_machine_api(
    machine_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    return _machine_to_dict(await _get_machine_or_404(machine_id, db, user))


@router.get("/machines/{machine_id}/packages", dependencies=[_view_machines])
async def list_machine_packages_api(
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    q: str = "",
    pkg_source: str = "",
    held_only: bool = False,
    user: User = Depends(get_api_token_user),
) -> list[dict[str, object]]:
    await _get_machine_or_404(machine_id, db, user)
    query = select(MachinePackage).where(MachinePackage.machine_id == machine_id)
    if q.strip():
        query = query.where(MachinePackage.name.ilike(f"%{q.strip()}%"))
    if pkg_source in {source.value for source in PackageSource}:
        query = query.where(MachinePackage.source == PackageSource(pkg_source))
    if held_only:
        query = query.where(MachinePackage.held.is_(True))
    result = await db.execute(query.order_by(MachinePackage.source, MachinePackage.name))
    return [_package_to_dict(p) for p in result.scalars().all()]


@router.get("/machines/{machine_id}/packages/held", dependencies=[_view_machines])
async def list_machine_held_packages_api(
    machine_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> list[dict[str, object]]:
    await _get_machine_or_404(machine_id, db, user)
    result = await db.execute(
        select(MachinePackage)
        .where(MachinePackage.machine_id == machine_id, MachinePackage.held.is_(True))
        .order_by(MachinePackage.name)
    )
    return [_package_to_dict(p) for p in result.scalars().all()]


@router.get("/machines/{machine_id}/services", dependencies=[_view_machines])
async def list_machine_services_api(
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    q: str = "",
    state: str = "",
    user: User = Depends(get_api_token_user),
) -> list[dict[str, object]]:
    """The Monitoring tab's systemd services table, with the same
    per-service CPU/memory columns (see MachineService)."""
    await _get_machine_or_404(machine_id, db, user)
    query = select(MachineService).where(MachineService.machine_id == machine_id)
    if q.strip():
        query = query.where(MachineService.unit.ilike(f"%{q.strip()}%"))
    if state:
        query = query.where(MachineService.active_state == state)
    result = await db.execute(query.order_by(MachineService.unit))
    return [
        {
            "unit": s.unit,
            "load_state": s.load_state,
            "active_state": s.active_state,
            "sub_state": s.sub_state,
            "description": s.description,
            "cpu_percent": s.cpu_percent,
            "cpu_percent_peak": s.cpu_percent_peak,
            "memory_bytes": s.memory_bytes,
            "memory_peak_bytes": s.memory_peak_bytes,
        }
        for s in result.scalars().all()
    ]


@router.get("/machines/{machine_id}/hardware", dependencies=[_view_machines])
async def get_machine_hardware_api(
    machine_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    """Everything the Monitoring tab shows beyond the trend graphs, as of
    the latest readings: S.M.A.R.T. detail (facts cadence), Docker
    containers, and the most recent sample's sensors/fans/GPUs."""
    machine = await _get_machine_or_404(machine_id, db, user)
    latest = (
        await db.execute(
            select(MachineMonitoringSample)
            .where(MachineMonitoringSample.machine_id == machine_id)
            .order_by(MachineMonitoringSample.sampled_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    return {
        "is_physical": machine.is_physical,
        "smart_devices": machine.smart_devices,
        "docker_status": machine.docker_status,
        "docker_containers": machine.docker_containers,
        "disk_forecast": machine.disk_forecast,
        "docker_image_updates": machine.docker_image_updates,
        "docker_images_checked_at": (
            machine.docker_images_checked_at.isoformat()
            if machine.docker_images_checked_at
            else None
        ),
        "sampled_at": latest.sampled_at.isoformat() if latest else None,
        "sensor_temps": latest.sensor_temps if latest else None,
        "sensor_fans": latest.sensor_fans if latest else None,
        "gpus": latest.gpus if latest else None,
        "gpu_power_watts": latest.gpu_power_watts if latest else None,
    }


@router.get("/machines/{machine_id}/update-runs", dependencies=[_view_machines])
async def list_machine_update_runs_api(
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    status_filter: str = "",
    page: int = 1,
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    """The API equivalent of `GET /machines/{id}/updates` — every update run
    for this machine, newest first, paginated/filterable the same way."""
    await _get_machine_or_404(machine_id, db, user)
    page = max(page, 1)

    query = select(MachineUpdateRun).where(MachineUpdateRun.machine_id == machine_id)
    if status_filter in {s.value for s in UpdateRunStatus}:
        query = query.where(MachineUpdateRun.status == UpdateRunStatus(status_filter))

    offset = (page - 1) * _UPDATE_RUNS_PAGE_SIZE
    result = await db.execute(
        query.order_by(MachineUpdateRun.created_at.desc())
        .offset(offset)
        .limit(_UPDATE_RUNS_PAGE_SIZE + 1)
    )
    runs = list(result.scalars().all())
    has_older = len(runs) > _UPDATE_RUNS_PAGE_SIZE
    runs = runs[:_UPDATE_RUNS_PAGE_SIZE]
    return {
        "runs": [_update_run_to_dict(r) for r in runs],
        "page": page,
        "has_older": has_older,
    }


@router.get("/machines/{machine_id}/update-runs/{run_id}", dependencies=[_view_machines])
async def get_machine_update_run_api(
    machine_id: uuid.UUID,
    run_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    """One update run — what a script polls after `POST .../updates` until
    `status` is no longer `pending`/`running`."""
    await _get_machine_or_404(machine_id, db, user)
    run = await db.get(MachineUpdateRun, run_id)
    if run is None or run.machine_id != machine_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    return _update_run_to_dict(run)


@router.get("/machines/{machine_id}/monitoring", dependencies=[_view_machines])
async def get_machine_monitoring_api(
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    range_key: str = Query(
        monitoring_history.DEFAULT_TIME_RANGE,
        description="One of " + ", ".join(k for k, _l, _d in monitoring_history.TIME_RANGES),
    ),
    start: datetime | None = Query(
        None, description="With `end`: a custom window instead of `range_key` (ISO 8601)."
    ),
    end: datetime | None = Query(None, description="End of the custom window (ISO 8601)."),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    """The Monitoring tab's trend graphs as data: CPU/RAM/load, network and
    disk I/O rates, filesystem usage and availability/latency, downsampled
    to ~150 points over `range_key` (`bucket_timestamps` is the shared X
    axis), plus the latest raw readings. `/hardware` has the rest of the
    tab (S.M.A.R.T., Docker, sensors)."""
    await _get_machine_or_404(machine_id, db, user)
    window = monitoring_history.resolve_window(range_key, _as_utc(start), _as_utc(end))
    history, availability = await monitoring_history.load_machine_history(
        db, machine_id, window
    )
    encoded: dict[str, object] = jsonable_encoder(
        {"monitoring": asdict(history), "availability": asdict(availability)}
    )
    return {
        "range_key": window.range_key,
        "since": window.since.isoformat(),
        "until": window.until.isoformat() if window.until else None,
        **encoded,
    }


@router.post("/machines/{machine_id}/monitoring/refresh", dependencies=[_manage_machines])
async def refresh_monitoring_api(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    """The Monitoring tab's "Refresh now": a fresh monitoring sample,
    reachability check and services snapshot, waited for together."""
    machine = await _get_machine_or_404(machine_id, db, user)
    app_settings = await get_or_create_app_settings(db)

    monitoring_result = tasks.sample_machine_monitoring.delay(str(machine.id))
    reachability_result = tasks.check_machine_reachability_now.delay(str(machine.id))
    services_result = tasks.refresh_machine_services.delay(str(machine.id))
    error: str | None = None
    try:
        results = await asyncio.gather(
            asyncio.to_thread(
                monitoring_result.get, timeout=app_settings.ssh_connect_timeout + 30
            ),
            asyncio.to_thread(
                reachability_result.get, timeout=app_settings.ssh_connect_timeout + 15
            ),
            asyncio.to_thread(services_result.get, timeout=app_settings.ssh_connect_timeout + 15),
        )
        for result in results:
            if isinstance(result, dict) and not result.get("ok"):
                error = str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        error = "The background job did not respond in time."
    except Exception as exc:
        error = str(exc)

    await log_event(
        db,
        request=request,
        action="machine.monitoring.refresh",
        summary=f'Refreshed monitoring for "{machine.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"error": error} if error else None,
    )
    if error is not None:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=error)
    return {"ok": True}


# --- Machines: writes --------------------------------------------------------


@router.post("/machines", dependencies=[_manage_machines], status_code=status.HTTP_201_CREATED)
async def create_machine_api(
    request: Request, payload: MachineCreate, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    await _require_group_in_scope(db, user, payload.group_id)
    machine = Machine(
        name=payload.name,
        ip_address=payload.ip_address,
        port=payload.port,
        username=payload.username,
        auth_method=payload.auth_method,
        secret_encrypted=encrypt_secret(payload.secret) if payload.secret else None,
        group_id=payload.group_id,
        description=payload.description,
        runbook=payload.runbook,
    )
    db.add(machine)
    await db.commit()
    await db.refresh(machine)
    machine = await _get_machine_or_404(machine.id, db, user)
    await set_machine_tags(db, machine, payload.tags)
    await db.commit()
    machine = await _get_machine_or_404(machine.id, db, user)

    await log_event(
        db,
        request=request,
        action="machine.create",
        summary=f'Created machine "{machine.name}" ({machine.ip_address})',
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
    )
    return _machine_to_dict(machine)


@router.put("/machines/{machine_id}", dependencies=[_manage_machines])
async def update_machine_api(
    request: Request,
    machine_id: uuid.UUID,
    payload: MachineUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    machine = await _get_machine_or_404(machine_id, db, user)
    await _require_group_in_scope(db, user, payload.group_id)

    connection_target_changed = (
        payload.ip_address != machine.ip_address or payload.port != machine.port
    )

    machine.name = payload.name
    machine.ip_address = payload.ip_address
    machine.port = payload.port
    machine.username = payload.username
    machine.auth_method = payload.auth_method
    machine.group_id = payload.group_id
    machine.description = payload.description
    machine.runbook = payload.runbook
    machine.is_active = payload.is_active
    await set_machine_tags(db, machine, payload.tags)

    if payload.auth_method == AuthMethod.PASSWORD:
        if payload.secret:
            machine.secret_encrypted = encrypt_secret(payload.secret)
    else:
        machine.secret_encrypted = None

    if connection_target_changed:
        machine.host_key_fingerprint = None
        machine.discovered_hostname = None
        machine.os_version = None
        machine.os_id = None
        machine.kernel_version = None
        machine.cpu_cores = None
        machine.cpu_model = None
        machine.ram_bytes = None
        machine.ram_speed_mhz = None
        machine.disks = None
        machine.facts_updated_at = None

    await db.commit()
    machine = await _get_machine_or_404(machine.id, db, user)

    await log_event(
        db,
        request=request,
        action="machine.update",
        summary=f'Updated machine "{machine.name}"',
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"connection_target_changed": connection_target_changed},
    )
    return _machine_to_dict(machine)


class _ConfirmDelete(BaseModel):
    """Echoing the target's own name back is the API equivalent of the web
    UI's typed-confirmation page for an irreversible action."""

    confirm_name: str = Field(min_length=1)


@router.delete("/machines/{machine_id}", dependencies=[_manage_machines])
async def delete_machine_api(
    request: Request,
    machine_id: uuid.UUID,
    payload: _ConfirmDelete,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, user)
    if payload.confirm_name.strip() != machine.name:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f'"confirm_name" must exactly match the machine\'s name ("{machine.name}").',
        )
    machine_name = machine.name
    await db.delete(machine)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="machine.delete",
        summary=f'Deleted machine "{machine_name}"',
        target_type="machine",
        target_id=machine_id,
        target_label=machine_name,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- Machines: on-demand checks and refreshes --------------------------------
# Each of these blocks on the same background job the web UI's equivalent
# button waits for, and returns once it's done rather than requiring the
# caller to poll — see each web route in `app/web/routes/machines.py` for
# the identical pattern this mirrors.


@router.post("/machines/{machine_id}/test-connection", dependencies=[_manage_machines])
async def test_connection_api(
    request: Request, machine_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    machine = await _get_machine_or_404(machine_id, db, user)
    app_settings = await get_or_create_app_settings(db)

    async_result = tasks.test_machine_connection.delay(str(machine.id))
    result: dict[str, object] | None = None
    error: str | None = None
    try:
        result = await asyncio.to_thread(
            async_result.get, timeout=app_settings.ssh_connect_timeout + 5
        )
    except CeleryTimeoutError:
        error = "The background job did not respond in time."
    except Exception as exc:
        error = str(exc)

    await log_event(
        db,
        request=request,
        action="machine.test_connection",
        summary=f'Tested connection to "{machine.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"error": error} if error else None,
    )
    if error is not None:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=error)
    return result or {"ok": True}


@router.post("/machines/{machine_id}/discover-host-key", dependencies=[_manage_machines])
async def discover_host_key_api(
    request: Request, machine_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    machine = await _get_machine_or_404(machine_id, db, user)
    app_settings = await get_or_create_app_settings(db)

    fingerprint: str | None = None
    error: str | None = None
    try:
        fingerprint = await discover_host_key_fingerprint(
            machine.ip_address, machine.port, app_settings.ssh_connect_timeout
        )
    except SSHConnectionError as exc:
        error = str(exc)

    await log_event(
        db,
        request=request,
        action="machine.host_key.discover",
        summary=f'Discovered host key fingerprint for "{machine.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"error": error} if error else None,
    )
    if error is not None:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=error)
    return {"fingerprint": fingerprint}


class _TrustHostKey(BaseModel):
    fingerprint: str = Field(min_length=1)


@router.post("/machines/{machine_id}/trust-host-key", dependencies=[_manage_machines])
async def trust_host_key_api(
    request: Request,
    machine_id: uuid.UUID,
    payload: _TrustHostKey,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    machine = await _get_machine_or_404(machine_id, db, user)
    fingerprint = payload.fingerprint.strip()
    if not _FINGERPRINT_RE.match(fingerprint):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid fingerprint format."
        )
    machine.host_key_fingerprint = fingerprint
    await db.commit()

    await log_event(
        db,
        request=request,
        action="machine.host_key.trust",
        summary=f'Trusted host key fingerprint for "{machine.name}"',
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"fingerprint": fingerprint},
    )
    # Same follow-up the web UI's equivalent kicks off: an initial facts pass
    # and a readiness check, both fire-and-forget.
    tasks.refresh_machine_facts.delay(str(machine.id))
    tasks.check_machine_readiness.delay(str(machine.id))
    return {"ok": True}


@router.post("/machines/{machine_id}/refresh-facts", dependencies=[_manage_machines])
async def refresh_facts_api(
    request: Request, machine_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    machine = await _get_machine_or_404(machine_id, db, user)
    app_settings = await get_or_create_app_settings(db)

    async_result = tasks.refresh_machine_facts.delay(str(machine.id))
    error: str | None = None
    try:
        result = await asyncio.to_thread(
            async_result.get, timeout=app_settings.ssh_connect_timeout + 5
        )
        if isinstance(result, dict) and not result.get("ok"):
            error = str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        error = "The background job did not respond in time."
    except Exception as exc:
        error = str(exc)

    if error is None:
        machine = await _get_machine_or_404(machine_id, db, user)

    await log_event(
        db,
        request=request,
        action="machine.facts.refresh",
        summary=f'Refreshed facts for "{machine.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"error": error} if error else None,
    )
    if error is not None:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=error)
    return _machine_to_dict(machine)


@router.post("/machines/{machine_id}/refresh-packages", dependencies=[_manage_machines])
async def refresh_packages_api(
    request: Request, machine_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    machine = await _get_machine_or_404(machine_id, db, user)
    app_settings = await get_or_create_app_settings(db)

    async_result = tasks.refresh_machine_packages.delay(str(machine.id))
    error: str | None = None
    try:
        result = await asyncio.to_thread(
            async_result.get, timeout=app_settings.ssh_connect_timeout + 15
        )
        if isinstance(result, dict) and not result.get("ok"):
            error = str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        error = "The background job did not respond in time."
    except Exception as exc:
        error = str(exc)

    await log_event(
        db,
        request=request,
        action="machine.packages.refresh",
        summary=f'Refreshed installed packages for "{machine.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"error": error} if error else None,
    )
    if error is not None:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=error)
    return {"ok": True}


@router.post("/machines/{machine_id}/refresh-services", dependencies=[_manage_machines])
async def refresh_services_api(
    request: Request, machine_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    machine = await _get_machine_or_404(machine_id, db, user)
    app_settings = await get_or_create_app_settings(db)

    async_result = tasks.refresh_machine_services.delay(str(machine.id))
    error: str | None = None
    try:
        result = await asyncio.to_thread(
            async_result.get, timeout=app_settings.ssh_connect_timeout + 15
        )
        if isinstance(result, dict) and not result.get("ok"):
            error = str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        error = "The background job did not respond in time."
    except Exception as exc:
        error = str(exc)

    await log_event(
        db,
        request=request,
        action="machine.services.refresh",
        summary=f'Refreshed services for "{machine.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"error": error} if error else None,
    )
    if error is not None:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=error)
    return {"ok": True}


@router.post("/machines/{machine_id}/run-onboarding", dependencies=[_manage_machines])
async def run_onboarding_api(
    request: Request, machine_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    """Runs initial setup using the credential already stored on the
    machine record. See this module's docstring for why the "Fix it"
    variant that submits a fresh one-time credential is not exposed here."""
    machine = await _get_machine_or_404(machine_id, db, user)
    app_settings = await get_or_create_app_settings(db)

    async_result = tasks.run_machine_onboarding.delay(str(machine.id))
    error: str | None = None
    output: str | None = None
    try:
        result = await asyncio.to_thread(
            async_result.get, timeout=app_settings.ssh_connect_timeout + 120
        )
        if isinstance(result, dict):
            if result.get("ok"):
                output = str(result.get("output") or "")
            else:
                error = str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        error = "The setup script did not finish in time."
    except Exception as exc:
        error = str(exc)

    await log_event(
        db,
        request=request,
        action="machine.onboarding.run",
        summary=f'Ran initial setup on "{machine.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"error": error} if error else None,
    )
    if error is None:
        tasks.check_machine_readiness.delay(str(machine.id))
    else:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=error)
    return {"ok": True, "output": output}


@router.post("/machines/{machine_id}/fix-readiness-directly", dependencies=[_manage_machines])
async def fix_readiness_directly_api(
    request: Request, machine_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    """Installs `ncurses-term` using the credential already stored on the
    machine record — the readiness banner's "Install now" button for a
    machine connected as root, where there is no sudo gap left to fix (see
    `app.ssh.readiness`'s module docstring). Uses only the credential
    already on file, same as `run_onboarding_api` above, so it's exposed
    here for the same reason that one is."""
    machine = await _get_machine_or_404(machine_id, db, user)
    app_settings = await get_or_create_app_settings(db)

    async_result = tasks.fix_root_readiness.delay(str(machine.id))
    error: str | None = None
    try:
        result = await asyncio.to_thread(
            async_result.get, timeout=app_settings.ssh_connect_timeout + 60
        )
        if isinstance(result, dict) and not result.get("ok"):
            error = str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        error = "Timed out."
    except Exception as exc:
        error = str(exc)

    await log_event(
        db,
        request=request,
        action="machine.readiness.fix_directly",
        summary=f'Installed missing readiness packages directly on "{machine.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"error": error} if error else None,
    )
    if error is not None:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=error)
    return {"ok": True}


@router.post("/machines/{machine_id}/recheck-readiness", dependencies=[_manage_machines])
async def recheck_readiness_api(
    request: Request, machine_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    machine = await _get_machine_or_404(machine_id, db, user)
    app_settings = await get_or_create_app_settings(db)

    async_result = tasks.check_machine_readiness.delay(str(machine.id))
    with contextlib.suppress(Exception):
        await asyncio.to_thread(async_result.get, timeout=app_settings.ssh_connect_timeout + 15)
    return {"ok": True}


@router.post("/machines/{machine_id}/docker/check-images", dependencies=[_manage_machines])
async def check_image_updates_api(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    """Run the Docker image update check now; returns `{image: status}`."""
    machine = await _get_machine_or_404(machine_id, db, user)
    app_settings = await get_or_create_app_settings(db)
    error: str | None = None
    try:
        async_result = tasks.check_machine_image_updates.delay(str(machine.id))
        result = await asyncio.to_thread(
            async_result.get, timeout=app_settings.ssh_connect_timeout + 150
        )
        if isinstance(result, dict) and not result.get("ok"):
            error = str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        error = "The check did not finish in time."
    except Exception as exc:
        error = str(exc)
    await log_event(
        db,
        request=request,
        action="machine.docker.check_images",
        summary=f'Checked Docker image updates on "{machine.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"error": error} if error else None,
    )
    if error is not None:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=error)
    await db.refresh(machine)
    return {"ok": True, "images": machine.docker_image_updates or {}}


@router.post(
    "/machines/{machine_id}/containers/{container}/{action}", dependencies=[_action_power]
)
async def container_action_api(
    request: Request,
    machine_id: uuid.UUID,
    container: str,
    action: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    """Start/stop/restart one Docker container — the API equivalent of the
    Monitoring tab's container actions, same `action.power` permission."""
    machine = await _get_machine_or_404(machine_id, db, user)
    if action not in CONTAINER_ACTIONS or not is_container_name_valid(container):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid request.")
    app_settings = await get_or_create_app_settings(db)

    output = ""
    error: str | None = None
    try:
        async_result = tasks.run_container_action_task.delay(
            str(machine.id), action=action, container=container
        )
        result = await asyncio.to_thread(
            async_result.get, timeout=app_settings.ssh_connect_timeout + 90
        )
        if isinstance(result, dict):
            if result.get("ok"):
                output = str(result.get("output") or "")
            else:
                error = str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        error = "The command did not finish in time."
    except Exception as exc:
        error = str(exc)

    await log_event(
        db,
        request=request,
        action=f"machine.container.{action}",
        summary=f'Container "{container}" {action} on "{machine.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"container": container, **({"error": error} if error else {})},
    )
    if error is not None:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=error)
    return {"ok": True, "output": output}


@router.get("/machines/{machine_id}/logs", dependencies=[_action_terminal])
async def machine_logs_api(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    path: str = "",
    lines: int = ssh_logs.DEFAULT_LINE_LIMIT,
    search: str = "",
    since: str = "",
    until: str = "",
    container: str = "",
    priority: str = "",
    unit: str = "",
    boot: str = "",
    hide_own: bool = False,
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    """The API equivalent of `GET /machines/{id}/logs` — journal by default
    (`priority` = a journalctl level such as `err` shows that level and
    worse, `unit` = one systemd unit, `boot` = 0 for this boot or -1, -2, …
    for earlier ones, `hide_own=true` drops debcontrol's own SSH logins),
    one allow-listed file when `path` is given, or one Docker container's
    logs when `container` is given. A journal read also returns `entries`
    (`{"text", "priority"}` per line, journald priority 0-7) and `hidden`. Gated behind
    `ACTION_TERMINAL`, same as the web route, not `MACHINE_VIEW` — see
    `app.ssh.logs`'s module docstring for why. Never stored anywhere."""
    machine = await _get_machine_or_404(machine_id, db, user)
    app_settings = await get_or_create_app_settings(db)

    if not machine.host_key_fingerprint:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Confirm the host key fingerprint before viewing logs.",
        )

    clamped_lines = max(1, min(lines, ssh_logs.MAX_LINE_LIMIT))
    output: str | None = None
    error: str | None = None
    extra: dict[str, object] = {}
    try:
        if container.strip():
            async_result = tasks.view_machine_docker_logs.delay(
                str(machine.id),
                container=container.strip(),
                lines=clamped_lines,
                search=search,
                since=since,
                until=until,
            )
        elif path.strip():
            async_result = tasks.view_machine_log_file.delay(
                str(machine.id), path=path.strip(), lines=clamped_lines, search=search
            )
        else:
            journal_options: dict[str, object] = {}
            if ssh_logs.normalize_priority(priority):
                journal_options["priority"] = ssh_logs.normalize_priority(priority)
            if ssh_logs.normalize_unit(unit):
                journal_options["unit"] = ssh_logs.normalize_unit(unit)
            if ssh_logs.normalize_boot(boot):
                journal_options["boot"] = ssh_logs.normalize_boot(boot)
            if hide_own:
                journal_options["hide_own"] = True
            async_result = tasks.view_machine_journal.delay(
                str(machine.id),
                lines=clamped_lines,
                search=search,
                since=since,
                until=until,
                **journal_options,
            )
        result = await asyncio.to_thread(
            async_result.get, timeout=app_settings.ssh_connect_timeout + 15
        )
        if isinstance(result, dict):
            if result.get("ok"):
                output = str(result.get("output") or "")
                if "entries" in result:
                    extra = {"entries": result["entries"], "hidden": result.get("hidden", 0)}
            else:
                error = str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        error = "The command did not finish in time."
    except Exception as exc:
        error = str(exc)

    await log_event(
        db,
        request=request,
        action="machine.logs.view",
        summary=(
            f'Viewed Docker logs of "{container.strip()}" on "{machine.name}"'
            if container.strip()
            else f'Viewed log file "{path.strip()}" on "{machine.name}"'
            if path.strip()
            else f'Viewed journal on "{machine.name}"'
        ),
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"search": search} if search.strip() else None,
    )
    if error is not None:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=error)
    return {"output": output or "", **extra}


@router.get("/machines/{machine_id}/logs/browse", dependencies=[_action_terminal])
async def machine_logs_browse_api(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    path: str = "",
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    """The API equivalent of `GET /machines/{id}/logs/browse` — lists what's
    directly inside an allowed directory (defaulting to the first configured
    `LOG_FILE_ALLOWED_PATHS` entry) so a script doesn't need a file's exact
    path already known either. Gated behind `ACTION_TERMINAL`, same as the
    rest of the Logs API. Never stored anywhere."""
    machine = await _get_machine_or_404(machine_id, db, user)
    app_settings = await get_or_create_app_settings(db)
    allowed_paths = get_settings().log_file_allowed_path_list
    current_path = path.strip() or (allowed_paths[0] if allowed_paths else "")

    if not machine.host_key_fingerprint:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Confirm the host key fingerprint before browsing logs.",
        )
    if not current_path:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No allowed log paths are configured.",
        )

    entries: list[dict[str, object]] = []
    error: str | None = None
    try:
        async_result = tasks.browse_machine_log_directory.delay(str(machine.id), path=current_path)
        result = await asyncio.to_thread(
            async_result.get, timeout=app_settings.ssh_connect_timeout + 15
        )
        if isinstance(result, dict):
            if result.get("ok"):
                entries = list(result.get("entries") or [])
            else:
                error = str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        error = "The command did not finish in time."
    except Exception as exc:
        error = str(exc)

    await log_event(
        db,
        request=request,
        action="machine.logs.browse",
        summary=f'Browsed "{current_path}" on "{machine.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
    )
    if error is not None:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=error)
    return {"path": current_path, "entries": entries}


# --- Bulk actions (ad-hoc selection from the machine list) ------------------


class _BulkMachineIds(BaseModel):
    machine_ids: list[uuid.UUID] = Field(min_length=1)


class _BulkUpdatesTrigger(_BulkMachineIds):
    strategy: UpgradeStrategy


class _BulkPowerAction(_BulkMachineIds):
    action: PowerAction
    confirm: str = Field(
        min_length=1,
        description=f'Must be exactly "{_BULK_POWER_CONFIRM_PHRASE}" to confirm.',
    )


class _BulkTags(_BulkMachineIds):
    tags: list[str] = Field(min_length=1)

    @field_validator("tags")
    @classmethod
    def _normalize_tags(cls, value: list[str]) -> list[str]:
        return normalize_tag_names(value)


async def _get_machines_by_ids(
    machine_ids: list[uuid.UUID], db: AsyncSession, user: User
) -> list[Machine]:
    """Submitted ids, minus anything outside this account's scope — dropped
    silently, same as the web UI's bulk endpoints."""
    return await visible_machines_by_ids(db, user, machine_ids)


@router.post("/machines/bulk/check-updates", dependencies=[_action_updates])
async def bulk_check_updates_api(
    request: Request, payload: _BulkMachineIds, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    machines = await _get_machines_by_ids(payload.machine_ids, db, user)
    skipped = await trigger_check_updates(machines)
    await log_event(
        db,
        request=request,
        action="machines.bulk.updates.check",
        summary=f"Checked for updates on {len(machines)} selected machine(s)",
        details={"machine_count": len(machines), "skipped": skipped},
    )
    return {"machine_count": len(machines), "skipped": skipped}


@router.post("/machines/bulk/updates", dependencies=[_action_updates])
async def bulk_trigger_updates_api(
    request: Request, payload: _BulkUpdatesTrigger, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    machines = await _get_machines_by_ids(payload.machine_ids, db, user)
    batch_id, skipped = await trigger_updates(db, machines, payload.strategy)
    await log_event(
        db,
        request=request,
        action="machines.bulk.updates.run",
        summary=(
            f'Triggered {payload.strategy.value.replace("_", "-")} on '
            f"{len(machines)} selected machine(s)"
        ),
        details={"strategy": payload.strategy.value, "batch_id": str(batch_id), "skipped": skipped},
    )
    return {"batch_id": str(batch_id), "skipped": skipped}


@router.post("/machines/bulk/power", dependencies=[_action_power])
async def bulk_power_action_api(
    request: Request, payload: _BulkPowerAction, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    if payload.confirm.strip() != _BULK_POWER_CONFIRM_PHRASE:
        await log_event(
            db,
            request=request,
            action=f"machines.bulk.power.{payload.action.value}",
            summary=(
                f"Blocked {payload.action.value} on {len(payload.machine_ids)} selected "
                "machine(s): confirmation mismatch"
            ),
            outcome=AuditOutcome.DENIED,
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f'"confirm" must be exactly "{_BULK_POWER_CONFIRM_PHRASE}".',
        )
    machines = await _get_machines_by_ids(payload.machine_ids, db, user)
    skipped = await send_power_to_machines(machines, payload.action)
    await log_event(
        db,
        request=request,
        action=f"machines.bulk.power.{payload.action.value}",
        summary=f"Sent {payload.action.value} to {len(machines)} selected machine(s)",
        details={"skipped": skipped},
    )
    return {"machine_count": len(machines), "skipped": skipped}


class _BulkGroup(_BulkMachineIds):
    # `null` = take the machines out of any group.
    group_id: uuid.UUID | None = None


@router.post("/machines/bulk/group", dependencies=[_manage_machines])
async def bulk_assign_group_api(
    request: Request, payload: _BulkGroup, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    """Move every machine in `payload.machine_ids` into `payload.group_id`
    (or out of any group with `null`) — the machine list's bulk "Move to
    group". Same scope rule as a single machine's group: a restricted
    account gets a 403 for a group it can't see, or for `null`."""
    await _require_group_in_scope(db, user, payload.group_id)
    group = await db.get(MachineGroup, payload.group_id) if payload.group_id else None
    if payload.group_id and group is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found.")
    machines = await _get_machines_by_ids(payload.machine_ids, db, user)
    moved = assign_machines_to_group(machines, group)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="machines.bulk.group.assign",
        summary=(
            f'Moved {len(moved)} selected machine(s) to group "{group.name}"'
            if group
            else f"Removed {len(moved)} selected machine(s) from their group"
        ),
        target_type="machine_group" if group else None,
        target_id=group.id if group else None,
        target_label=group.name if group else None,
        details={
            "group": group.name if group else None,
            "machines": [m.name for m in moved],
            "unchanged_count": len(machines) - len(moved),
        },
    )
    return {
        "group_id": str(group.id) if group else None,
        "moved": [str(m.id) for m in moved],
        "unchanged_count": len(machines) - len(moved),
    }


@router.post("/machines/bulk/tags/add", dependencies=[_manage_machines])
async def bulk_add_tags_api(
    request: Request, payload: _BulkTags, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    """Add `payload.tags` to every machine in `payload.machine_ids`, leaving
    each machine's other tags untouched — the API equivalent of the machine
    list's bulk "Add tags" button."""
    machines = await _get_machines_by_ids(payload.machine_ids, db, user)
    await add_tags_to_machines(db, [m.id for m in machines], payload.tags)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="machines.bulk.tags.add",
        summary=(
            f'Added tag(s) {", ".join(payload.tags)} to {len(machines)} selected machine(s)'
        ),
        details={"tags": payload.tags, "machine_count": len(machines)},
    )
    return {"machine_count": len(machines), "tags": payload.tags}


@router.post("/machines/bulk/tags/remove", dependencies=[_manage_machines])
async def bulk_remove_tags_api(
    request: Request, payload: _BulkTags, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    """Remove `payload.tags` from every machine in `payload.machine_ids` —
    a no-op for any machine that didn't have a given tag, never an error."""
    machines = await _get_machines_by_ids(payload.machine_ids, db, user)
    await remove_tags_from_machines(db, [m.id for m in machines], payload.tags)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="machines.bulk.tags.remove",
        summary=(
            f'Removed tag(s) {", ".join(payload.tags)} from {len(machines)} selected machine(s)'
        ),
        details={"tags": payload.tags, "machine_count": len(machines)},
    )
    return {"machine_count": len(machines), "tags": payload.tags}


@router.get("/machines/{machine_id}/updates/preview", dependencies=[_action_updates])
async def preview_machine_update_api(
    request: Request,
    machine_id: uuid.UUID,
    strategy: UpgradeStrategy = UpgradeStrategy.DIST_UPGRADE,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    """The API equivalent of the web UI's `GET /machines/{id}/updates/preview`
    — a dry-run simulation (apt's `-s` flag; nothing on the machine changes)
    of what `POST /machines/{id}/updates` would do, most importantly what
    `autoremove` would remove.

    Unlike the web UI, `POST /machines/{id}/updates` below is **not** forced
    through this preview first — a scripted/API caller presumably already
    knows what it's asking for (that's the whole point of automating it),
    the same reasoning that already applies to every other unconfirmed
    single-machine trigger in this file. This preview is offered as an
    optional tool for a caller that *wants* to check before triggering (or
    wants to render its own preview UI), not a mandatory gate — see this
    module's docstring for how that compares to the destructive actions
    here that *do* require an explicit `confirm`/`confirm_name` field."""
    machine = await _get_machine_or_404(machine_id, db, user)
    if not machine.host_key_fingerprint:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Confirm the host key fingerprint before previewing updates.",
        )

    async_result = preview_machine_update.delay(str(machine.id), strategy.value)
    app_settings = await get_or_create_app_settings(db)
    try:
        # `AsyncResult.get()` is a blocking, synchronous call — off the event
        # loop it goes, or it would stall every other in-flight request for
        # as long as this preview takes.
        result = await asyncio.to_thread(
            async_result.get, timeout=app_settings.update_timeout_seconds + 5
        )
    except CeleryTimeoutError as exc:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="The background job did not respond in time.",
        ) from exc
    if not isinstance(result, dict) or not result.get("ok"):
        error = str(result.get("error")) if isinstance(result, dict) else "Unknown error."
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=error)
    return {
        "to_install_or_upgrade": result.get("to_install_or_upgrade") or [],
        "to_remove": result.get("to_remove") or [],
    }


class _UpdatesTrigger(BaseModel):
    strategy: UpgradeStrategy


@router.post("/machines/{machine_id}/updates", dependencies=[_action_updates])
async def trigger_machine_update_api(
    request: Request,
    machine_id: uuid.UUID,
    payload: _UpdatesTrigger,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    machine = await _get_machine_or_404(machine_id, db, user)
    if not machine.host_key_fingerprint:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Confirm the host key fingerprint before running updates.",
        )
    run = MachineUpdateRun(machine_id=machine.id, strategy=payload.strategy)
    db.add(run)
    await db.commit()
    await db.refresh(run)
    run_machine_update.delay(str(run.id))

    await log_event(
        db,
        request=request,
        action="machine.updates.run",
        summary=f'Triggered {payload.strategy.value.replace("_", "-")} on "{machine.name}"',
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"strategy": payload.strategy.value, "run_id": str(run.id)},
    )
    return _update_run_to_dict(run)


@router.post("/machines/{machine_id}/updates/{run_id}/rollback", dependencies=[_action_updates])
async def rollback_machine_update_api(
    request: Request,
    machine_id: uuid.UUID,
    run_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    """The API equivalent of `POST /machines/{id}/updates/{run_id}/rollback`
    — see `app/web/routes/machines.py`'s `rollback_machine_update_endpoint`
    and `app.tasks.jobs._rollback_machine_update`."""
    machine = await _get_machine_or_404(machine_id, db, user)
    source_run = await db.get(MachineUpdateRun, run_id)
    if source_run is None or source_run.machine_id != machine.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Update run not found.")
    if source_run.status != UpdateRunStatus.SUCCEEDED or not source_run.package_snapshot:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This update run has no captured package snapshot to roll back to.",
        )
    if source_run.rollback_of_run_id is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Can't roll back a rollback."
        )

    rollback_run = MachineUpdateRun(
        machine_id=machine.id, strategy=source_run.strategy, rollback_of_run_id=source_run.id
    )
    db.add(rollback_run)
    await db.commit()
    await db.refresh(rollback_run)
    rollback_machine_update.delay(str(rollback_run.id))

    await log_event(
        db,
        request=request,
        action="machine.updates.rollback",
        summary=f'Triggered rollback of update run {source_run.id} on "{machine.name}"',
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"source_run_id": str(source_run.id), "rollback_run_id": str(rollback_run.id)},
    )
    return _update_run_to_dict(rollback_run)


@router.post("/machines/{machine_id}/check-updates", dependencies=[_action_updates])
async def check_machine_updates_api(
    request: Request, machine_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    machine = await _get_machine_or_404(machine_id, db, user)
    skipped = await trigger_check_updates([machine])
    await log_event(
        db,
        request=request,
        action="machine.updates.check",
        summary=f'Checked for updates on "{machine.name}"',
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"skipped": skipped},
    )
    return {"skipped": skipped}


async def _set_hold_api(
    request: Request, machine: Machine, package: str, *, hold: bool, db: AsyncSession
) -> dict[str, object]:
    if not is_safe_package_name(package):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid package name.")
    if not machine.host_key_fingerprint:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Confirm the host key fingerprint first.",
        )
    app_settings = await get_or_create_app_settings(db)
    error: str | None = None
    try:
        result = await asyncio.to_thread(
            tasks.set_machine_package_hold.delay(str(machine.id), package, hold).get,
            timeout=app_settings.ssh_connect_timeout + 90,
        )
        if isinstance(result, dict) and not result.get("ok"):
            error = str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        error = "The command did not finish in time."
    except Exception as exc:
        error = str(exc)
    await log_event(
        db,
        request=request,
        action="machine.package.hold" if hold else "machine.package.unhold",
        summary=f'{"Held" if hold else "Released"} package "{package}" on "{machine.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"package": package, **({"error": error} if error else {})},
    )
    if error is not None:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=error)
    await db.refresh(machine)
    return {"package": package, "held": hold, "apt_held_packages": machine.apt_held_packages}


@router.post("/machines/{machine_id}/packages/{package}/hold", dependencies=[_action_updates])
async def hold_package_api(
    request: Request,
    machine_id: uuid.UUID,
    package: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    """`apt-mark hold` one package — no update run upgrades it until it is
    released (`DELETE` on the same path). Same permission as running
    updates; needs root or a sudoers grant for `apt-mark`."""
    machine = await _get_machine_or_404(machine_id, db, user)
    return await _set_hold_api(request, machine, package, hold=True, db=db)


@router.delete("/machines/{machine_id}/packages/{package}/hold", dependencies=[_action_updates])
async def release_package_api(
    request: Request,
    machine_id: uuid.UUID,
    package: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    """`apt-mark unhold` — the reverse of `POST .../hold`."""
    machine = await _get_machine_or_404(machine_id, db, user)
    return await _set_hold_api(request, machine, package, hold=False, db=db)


@router.get("/machines/{machine_id}/packages/{package}/changelog", dependencies=[_view_machines])
async def package_changelog_api(
    machine_id: uuid.UUID,
    package: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    """What changed in a pending apt update since the installed version
    (`apt-get changelog`, fetched live, trimmed to the new entries)."""
    machine = await _get_machine_or_404(machine_id, db, user)
    if not is_safe_package_name(package):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid package name.")
    if not machine.host_key_fingerprint:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Confirm the host key fingerprint first.",
        )
    app_settings = await get_or_create_app_settings(db)
    try:
        result = await asyncio.to_thread(
            tasks.view_package_changelog.delay(str(machine.id), package).get,
            timeout=app_settings.ssh_connect_timeout + 60,
        )
    except CeleryTimeoutError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail="The command did not finish in time."
        ) from exc
    if not isinstance(result, dict) or not result.get("ok"):
        detail = str((result or {}).get("error") or "Unknown error.")
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=detail)
    return {
        "package": package,
        "installed_version": result.get("installed_version"),
        "changelog": result.get("changelog") or "",
    }


class _PowerAction(BaseModel):
    action: PowerAction
    confirm_name: str = Field(min_length=1)


@router.post("/machines/{machine_id}/power", dependencies=[_action_power])
async def machine_power_api(
    request: Request,
    machine_id: uuid.UUID,
    payload: _PowerAction,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    machine = await _get_machine_or_404(machine_id, db, user)
    if payload.confirm_name.strip() != machine.name:
        await log_event(
            db,
            request=request,
            action=f"machine.power.{payload.action.value}",
            summary=f'Blocked {payload.action.value} on "{machine.name}": confirmation mismatch',
            outcome=AuditOutcome.DENIED,
            target_type="machine",
            target_id=machine.id,
            target_label=machine.name,
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f'"confirm_name" must exactly match the machine\'s name ("{machine.name}").',
        )
    if not machine.host_key_fingerprint:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Confirm the host key fingerprint before sending power commands.",
        )
    send_machine_power_command.delay(str(machine.id), payload.action.value)
    await log_event(
        db,
        request=request,
        action=f"machine.power.{payload.action.value}",
        summary=f'Sent {payload.action.value} to "{machine.name}"',
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
    )
    return {"ok": True}




# --- Machine groups ----------------------------------------------------------


@router.get("/machine-groups", dependencies=[_view_groups])
async def list_machine_groups_api(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> list[dict[str, object]]:
    query = (await groups_visible_to(db, user)).options(selectinload(MachineGroup.machines))
    result = await db.execute(query)
    return [_group_to_dict(g) for g in result.scalars().all()]


@router.post(
    "/machine-groups", dependencies=[_manage_groups], status_code=status.HTTP_201_CREATED
)
async def create_machine_group_api(
    request: Request, payload: MachineGroupCreate, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    # A restricted account creating a group would create something it can't
    # then see (a new group is in nobody's grant set). Refusing is clearer
    # than silently handing back a group that vanishes on the next request.
    if await is_restricted(db, user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "This account is restricted to specific machine groups and can't "
                "create new ones."
            ),
        )
    group = MachineGroup(name=payload.name, description=payload.description)
    db.add(group)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f'A group named "{payload.name}" already exists.',
        ) from None
    group = await _get_group_or_404(group.id, db, user)
    await log_event(
        db,
        request=request,
        action="group.create",
        summary=f'Created group "{group.name}"',
        target_type="machine_group",
        target_id=group.id,
        target_label=group.name,
    )
    return _group_to_dict(group)


@router.get("/machine-groups/{group_id}", dependencies=[_view_groups])
async def get_machine_group_api(
    group_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    return _group_to_dict(await _get_group_or_404(group_id, db, user))


@router.get("/machine-groups/{group_id}/members", dependencies=[_view_groups])
async def list_group_members_api(
    group_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> list[dict[str, object]]:
    group = await _get_group_or_404(group_id, db, user)
    return [_machine_to_dict(m) for m in group.machines]


@router.put("/machine-groups/{group_id}", dependencies=[_manage_groups])
async def update_machine_group_api(
    request: Request,
    group_id: uuid.UUID,
    payload: MachineGroupCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    group = await _get_group_or_404(group_id, db, user)
    group.name = payload.name
    group.description = payload.description
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f'A group named "{payload.name}" already exists.',
        ) from None
    group = await _get_group_or_404(group.id, db, user)
    await log_event(
        db,
        request=request,
        action="group.update",
        summary=f'Updated group "{group.name}"',
        target_type="machine_group",
        target_id=group.id,
        target_label=group.name,
    )
    return _group_to_dict(group)


@router.delete("/machine-groups/{group_id}", dependencies=[_manage_groups])
async def delete_machine_group_api(
    request: Request, group_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> Response:
    group = await _get_group_or_404(group_id, db, user)
    group_name = group.name
    for machine in group.machines:
        machine.group_id = None
    await db.delete(group)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="group.delete",
        summary=f'Deleted group "{group_name}"',
        target_type="machine_group",
        target_id=group_id,
        target_label=group_name,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


class _GroupMachineId(BaseModel):
    machine_id: uuid.UUID


@router.post("/machine-groups/{group_id}/machines", dependencies=[_manage_groups])
async def add_machine_to_group_api(
    request: Request,
    group_id: uuid.UUID,
    payload: _GroupMachineId,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    group = await _get_group_or_404(group_id, db, user)
    machine = await db.get(Machine, payload.machine_id)
    # Out-of-scope reads as missing, so membership editing can't be used to
    # discover (or quietly reassign) a machine this account can't see.
    if machine is None or not await can_see_machine(db, user, machine):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Machine not found.")
    machine.group_id = group.id
    await db.commit()
    await log_event(
        db,
        request=request,
        action="group.machine.add",
        summary=f'Added "{machine.name}" to group "{group.name}"',
        target_type="machine_group",
        target_id=group.id,
        target_label=group.name,
        details={"machine_id": str(machine.id), "machine_name": machine.name},
    )
    return {"ok": True}


@router.delete("/machine-groups/{group_id}/machines/{machine_id}", dependencies=[_manage_groups])
async def remove_machine_from_group_api(
    request: Request,
    group_id: uuid.UUID,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> Response:
    await _get_group_or_404(group_id, db, user)
    machine = await db.get(Machine, machine_id)
    if (
        machine is not None
        and machine.group_id == group_id
        and await can_see_machine(db, user, machine)
    ):
        machine.group_id = None
        await db.commit()
        await log_event(
            db,
            request=request,
            action="group.machine.remove",
            summary=f'Removed "{machine.name}" from group',
            target_type="machine_group",
            target_id=group_id,
            details={"machine_id": str(machine.id), "machine_name": machine.name},
        )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- "All machines" (the built-in virtual group) -----------------------------


@router.post("/machine-groups/all/updates", dependencies=[_action_updates])
async def trigger_all_machines_update_api(
    request: Request,
    payload: _UpdatesTrigger,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    machines = await _visible_machines(db, user)
    batch_id, skipped = await trigger_updates(db, machines, payload.strategy)
    await log_event(
        db,
        request=request,
        action="all_machines.updates.run",
        summary=f"Triggered {payload.strategy.value.replace('_', '-')} on all machines",
        target_type="all_machines",
        details={"strategy": payload.strategy.value, "batch_id": str(batch_id), "skipped": skipped},
    )
    return {"batch_id": str(batch_id), "skipped": skipped}


@router.post("/machine-groups/all/check-updates", dependencies=[_action_updates])
async def trigger_all_check_updates_api(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    skipped = await trigger_check_updates(await _visible_machines(db, user))
    await log_event(
        db,
        request=request,
        action="all_machines.updates.check",
        summary="Checked for updates on all machines",
        target_type="all_machines",
        details={"skipped": skipped},
    )
    return {"skipped": skipped}


class _AllMachinesPowerAction(BaseModel):
    action: PowerAction
    confirm: str = Field(
        min_length=1, description=f'Must be exactly "{_ALL_MACHINES_CONFIRM_PHRASE}" to confirm.'
    )


@router.post("/machine-groups/all/power", dependencies=[_action_power])
async def all_power_action_api(
    request: Request,
    payload: _AllMachinesPowerAction,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    if payload.confirm.strip() != _ALL_MACHINES_CONFIRM_PHRASE:
        await log_event(
            db,
            request=request,
            action=f"all_machines.power.{payload.action.value}",
            summary=f"Blocked {payload.action.value} on all machines: confirmation mismatch",
            outcome=AuditOutcome.DENIED,
            target_type="all_machines",
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f'"confirm" must be exactly "{_ALL_MACHINES_CONFIRM_PHRASE}".',
        )
    machines = await _visible_machines(db, user)
    skipped = await send_power_to_machines(machines, payload.action)
    await log_event(
        db,
        request=request,
        action=f"all_machines.power.{payload.action.value}",
        summary=f"Sent {payload.action.value} to all machines",
        target_type="all_machines",
        details={"skipped": skipped},
    )
    return {"ok": True, "skipped": skipped}


@router.post("/machine-groups/{group_id}/updates", dependencies=[_action_updates])
async def trigger_group_update_api(
    request: Request,
    group_id: uuid.UUID,
    payload: _UpdatesTrigger,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    group = await _get_group_or_404(group_id, db, user)
    batch_id, skipped = await trigger_updates(db, group.machines, payload.strategy)
    await log_event(
        db,
        request=request,
        action="group.updates.run",
        summary=f'Triggered {payload.strategy.value.replace("_", "-")} on group "{group.name}"',
        target_type="machine_group",
        target_id=group.id,
        target_label=group.name,
        details={"strategy": payload.strategy.value, "batch_id": str(batch_id), "skipped": skipped},
    )
    return {"batch_id": str(batch_id), "skipped": skipped}


@router.post("/machine-groups/{group_id}/check-updates", dependencies=[_action_updates])
async def trigger_group_check_updates_api(
    request: Request, group_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    group = await _get_group_or_404(group_id, db, user)
    skipped = await trigger_check_updates(group.machines)
    await log_event(
        db,
        request=request,
        action="group.updates.check",
        summary=f'Checked for updates on group "{group.name}"',
        target_type="machine_group",
        target_id=group.id,
        target_label=group.name,
        details={"skipped": skipped},
    )
    return {"skipped": skipped}


class _GroupPowerAction(BaseModel):
    action: PowerAction
    confirm_name: str = Field(min_length=1)


@router.post("/machine-groups/{group_id}/power", dependencies=[_action_power])
async def group_power_action_api(
    request: Request,
    group_id: uuid.UUID,
    payload: _GroupPowerAction,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    group = await _get_group_or_404(group_id, db, user)
    if payload.confirm_name.strip() != group.name:
        await log_event(
            db,
            request=request,
            action=f"group.power.{payload.action.value}",
            summary=(
                f'Blocked {payload.action.value} on group "{group.name}": '
                "confirmation mismatch"
            ),
            outcome=AuditOutcome.DENIED,
            target_type="machine_group",
            target_id=group.id,
            target_label=group.name,
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f'"confirm_name" must exactly match the group\'s name ("{group.name}").',
        )
    skipped = await send_power_to_machines(group.machines, payload.action)
    await log_event(
        db,
        request=request,
        action=f"group.power.{payload.action.value}",
        summary=f'Sent {payload.action.value} to group "{group.name}"',
        target_type="machine_group",
        target_id=group.id,
        target_label=group.name,
        details={"skipped": skipped},
    )
    return {"ok": True, "skipped": skipped}



@router.get("/machine-groups/batches/{batch_id}", dependencies=[_view_machines])
async def update_batch_detail_api(
    batch_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    # Restricted to this account's own machines, so a batch that straddles
    # the boundary (an unrestricted admin's "All machines" run) reports only
    # the part this account can see.
    visible_ids = (await machines_visible_to(db, user)).with_only_columns(Machine.id)
    result = await db.execute(
        select(MachineUpdateRun)
        .options(selectinload(MachineUpdateRun.machine))
        .where(
            MachineUpdateRun.batch_id == batch_id,
            MachineUpdateRun.machine_id.in_(visible_ids),
        )
        .order_by(MachineUpdateRun.created_at)
    )
    runs = list(result.scalars().all())
    if not runs:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Batch not found.")
    return {"batch_id": str(batch_id), "runs": [_update_run_to_dict(r) for r in runs]}


@router.post("/machines/{machine_id}/acknowledge", dependencies=[_manage_machines])
async def acknowledge_machine_api(
    payload: AcknowledgeRequest,
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    """Acknowledge a problem on a machine: its notifications are withheld
    until it is reachable again, `hours` pass or the acknowledgement is
    deleted — see `app.services.acknowledgements`."""
    machine = await _get_machine_or_404(machine_id, db, user)
    acknowledgements.acknowledge(
        machine, by=user.username, note=payload.note, hours=payload.hours
    )
    await db.commit()
    await log_event(
        db,
        request=request,
        action="machine.acknowledge",
        summary=f'Acknowledged a problem on "{machine.name}" (REST API)',
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"hours": payload.hours, "note": machine.acknowledged_note},
    )
    return {"acknowledgement": acknowledgements.as_dict(machine)}


@router.delete(
    "/machines/{machine_id}/acknowledge",
    dependencies=[_manage_machines],
    status_code=status.HTTP_204_NO_CONTENT,
)
async def clear_machine_acknowledgement_api(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, user)
    acknowledgements.clear(machine)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="machine.acknowledge.clear",
        summary=f'Cleared the acknowledgement on "{machine.name}" (REST API)',
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
