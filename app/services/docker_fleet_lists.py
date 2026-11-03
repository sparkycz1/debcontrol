"""The fleet-wide Docker lists besides containers (`docker_fleet`): stacks,
images, volumes, networks, backups, hosts and jobs of every visible
machine, filtered and paged here so the web pages and their
`GET /api/v1/docker/...` twins answer the same.

Nothing is asked over SSH: stacks come from the containers' last sample
plus the stacks debcontrol manages, images / volumes / networks from the
stored inventory (`docker_inventory_snapshot`), backups and jobs from the
database, hosts from the stored host check.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.app_settings import AppSettings
from app.db.models.docker import DockerBackup, DockerJob, DockerJobStatus, DockerStack
from app.db.models.machine import Machine
from app.db.models.machine_group import MachineGroup
from app.db.models.user import User
from app.services import docker_daemon, docker_host_check, docker_jobs, self_host
from app.services import docker_inventory_snapshot as snapshot
from app.services.access_scope import machines_visible_to

PAGE_SIZE = 100
# A guard for very large fleets: a list stops here and says so.
MAX_ROWS = 20_000
JOBS_LIMIT = 500
KINDS = ("stacks", "images", "volumes", "networks", "backups", "hosts", "jobs")
# Each list's own filter (`FleetListFilter.show`).
SHOW = {
    "stacks": ("running", "stopped", "managed"),
    "images": ("unused", "dangling", "update"),
    "volumes": ("unused", "anonymous"),
    "networks": ("custom", "unused"),
    "backups": ("failed", "disabled"),
    "hosts": ("warnings", "differs", "restart"),
    "jobs": ("active", "failed"),
}


@dataclass(frozen=True)
class FleetListFilter:
    q: str = ""
    group_id: uuid.UUID | None = None
    show: str = ""
    page: int = 1

    @classmethod
    def parse(
        cls, kind: str, *, q: str = "", group: str = "", show: str = "", page: int = 1
    ) -> FleetListFilter:
        try:
            group_id = uuid.UUID(group) if group else None
        except ValueError:
            group_id = None
        return cls(
            q=q.strip()[:200],
            group_id=group_id,
            show=show if show in SHOW.get(kind, ()) else "",
            page=max(1, page),
        )


@dataclass
class FleetItem:
    machine_id: uuid.UUID
    machine_name: str
    machine_ready: bool
    group_name: str | None
    # What the row identifies on its machine (a project, image ref or id,
    # volume, network, backup id, job id); its checkbox sends
    # `<machine id>/<ident>`.
    ident: str
    item: dict[str, Any]
    is_own: bool = False

    @property
    def key(self) -> str:
        return f"{self.machine_id}/{self.ident}"


@dataclass
class FleetList:
    kind: str
    rows: list[FleetItem] = field(default_factory=list)
    total: int = 0
    page: int = 1
    pages: int = 1
    machines: int = 0
    truncated: bool = False
    # The oldest stored inventory among the machines listed (images,
    # volumes, networks), so the page can say how current it is.
    oldest_read: datetime | None = None
    # Machines with readable Docker but nothing stored yet.
    never_read: int = 0


async def docker_machines(
    db: AsyncSession, user: User, group_id: uuid.UUID | None
) -> list[Machine]:
    """Visible machines whose Docker could be read (optionally one group's)."""
    query = (await machines_visible_to(db, user)).where(Machine.docker_status == "ok")
    if group_id is not None:
        query = query.where(Machine.group_id == group_id)
    return list((await db.execute(query.order_by(Machine.name))).scalars().all())


async def _group_names(db: AsyncSession, machines: list[Machine]) -> dict[uuid.UUID, str]:
    ids = {m.group_id for m in machines if m.group_id is not None}
    if not ids:
        return {}
    result = await db.execute(
        select(MachineGroup.id, MachineGroup.name).where(MachineGroup.id.in_(ids))
    )
    return {row[0]: row[1] for row in result.all()}


def _text(*parts: Any) -> str:
    return " ".join(str(p) for p in parts if p).lower()


def _item(
    m: Machine, groups: dict[uuid.UUID, str], ident: str, item: dict[str, Any], **extra: Any
) -> FleetItem:
    return FleetItem(
        machine_id=m.id,
        machine_name=m.name,
        machine_ready=bool(m.host_key_fingerprint),
        group_name=groups.get(m.group_id) if m.group_id else None,
        ident=ident,
        item=item,
        **extra,
    )


def _stack_state(running: int, total: int, status: str) -> str:
    """From the containers' last sample; without one (not sampled yet),
    from what `docker compose ls` said, e.g. "exited(1), running(2)"."""
    if total:
        return "running" if running == total else ("partial" if running else "stopped")
    if "running" in status:
        return "partial" if any(w in status for w in ("exited", "paused", "dead")) else "running"
    return "stopped"


async def _stacks(
    db: AsyncSession, machines: list[Machine], groups: dict[uuid.UUID, str], show: str
) -> list[FleetItem]:
    ids = [m.id for m in machines]
    managed: dict[tuple[uuid.UUID, str], DockerStack] = {}
    if ids:
        result = await db.execute(select(DockerStack).where(DockerStack.machine_id.in_(ids)))
        managed = {(s.machine_id, s.name): s for s in result.scalars().all()}
    own = await self_host.find(db)
    rows: list[FleetItem] = []
    for m in machines:
        counts: dict[str, list[int]] = {}
        for c in m.docker_containers or []:
            project = isinstance(c, dict) and str(c.get("compose_project") or "")
            if project:
                entry = counts.setdefault(project, [0, 0])
                entry[1] += 1
                entry[0] += 1 if c.get("state") == "running" else 0
        stored = {str(p.get("name")): p for p in snapshot.rows(m, "projects")}
        names = set(counts) | set(stored) | {n for (mid, n) in managed if mid == m.id}
        protected = docker_jobs.own_project_of(m.id, m.docker_containers, own)
        for name in sorted(names):
            running, total = counts.get(name, [0, 0])
            stack = managed.get((m.id, name))
            status = str((stored.get(name) or {}).get("status") or "")
            state = _stack_state(running, total, status)
            if show == "running" and state == "stopped":
                continue
            if show == "stopped" and state != "stopped":
                continue
            if show == "managed" and stack is None:
                continue
            rows.append(
                _item(
                    m,
                    groups,
                    name,
                    {
                        "name": name,
                        "running": running,
                        "total": total,
                        "state": state,
                        "status": status,
                        "managed": stack is not None,
                        "stack_id": str(stack.id) if stack else None,
                        "source": stack.source if stack else None,
                        "drift": stack.drift_status if stack else None,
                        "last_status": stack.last_status if stack else None,
                    },
                    is_own=bool(protected and name == protected),
                )
            )
    return rows


def _images(
    machines: list[Machine], groups: dict[uuid.UUID, str], show: str
) -> list[FleetItem]:
    rows: list[FleetItem] = []
    for m in machines:
        updates = m.docker_image_updates if isinstance(m.docker_image_updates, dict) else {}
        for image in snapshot.rows(m, "images"):
            ref = str(image.get("ref") or "")
            status = updates.get(ref) if ref else None
            if show == "unused" and image.get("in_use"):
                continue
            if show == "dangling" and not image.get("dangling"):
                continue
            if show == "update" and status != "update":
                continue
            rows.append(
                _item(m, groups, ref or str(image.get("id")), {**image, "update": status})
            )
    return rows


def _volumes(
    machines: list[Machine], groups: dict[uuid.UUID, str], show: str
) -> list[FleetItem]:
    rows: list[FleetItem] = []
    for m in machines:
        for volume in snapshot.rows(m, "volumes"):
            if show == "unused" and volume.get("used_by"):
                continue
            if show == "anonymous" and not volume.get("anonymous"):
                continue
            rows.append(_item(m, groups, str(volume.get("name")), volume))
    return rows


def _networks(
    machines: list[Machine], groups: dict[uuid.UUID, str], show: str
) -> list[FleetItem]:
    rows: list[FleetItem] = []
    for m in machines:
        for network in snapshot.rows(m, "networks"):
            if show == "custom" and network.get("builtin"):
                continue
            if show == "unused" and (network.get("containers") or network.get("builtin")):
                continue
            rows.append(_item(m, groups, str(network.get("name")), network))
    return rows


async def _backups(
    db: AsyncSession, machines: list[Machine], groups: dict[uuid.UUID, str], show: str
) -> list[FleetItem]:
    by_id = {m.id: m for m in machines}
    if not by_id:
        return []
    result = await db.execute(
        select(DockerBackup)
        .where(DockerBackup.machine_id.in_(list(by_id)))
        .order_by(DockerBackup.name)
    )
    rows: list[FleetItem] = []
    for backup in result.scalars().all():
        if show == "failed" and "fail" not in str(backup.last_backup_status or "") + str(
            backup.last_check_status or ""
        ) + str(backup.last_verify_status or ""):
            continue
        if show == "disabled" and backup.enabled:
            continue
        m = by_id[backup.machine_id]
        rows.append(
            _item(
                m,
                groups,
                str(backup.id),
                {
                    "id": str(backup.id),
                    "name": backup.name,
                    "enabled": backup.enabled,
                    "repository": backup.repository_display,
                    "volumes": list(backup.volumes or []),
                    "paths": list(backup.paths or []),
                    "last_backup_at": backup.last_backup_at,
                    "last_backup_status": backup.last_backup_status,
                    "last_success_at": backup.last_success_at,
                    "last_backup_bytes": backup.last_backup_bytes,
                    "last_check_status": backup.last_check_status,
                    "last_verify_status": backup.last_verify_status,
                    "last_error": backup.last_error,
                },
            )
        )
    rows.sort(key=lambda r: (r.machine_name.lower(), str(r.item["name"]).lower()))
    return rows


async def _hosts(
    db: AsyncSession,
    machines: list[Machine],
    groups: dict[uuid.UUID, str],
    show: str,
    settings: AppSettings,
) -> list[FleetItem]:
    own = (await self_host.find(db)).hosts
    rows: list[FleetItem] = []
    for m in machines:
        check = m.docker_host_check or {}
        facts = check.get("facts") or {}
        daemon = docker_daemon.machine_status(m, settings)
        warnings = docker_host_check.warn_count(check)
        if show == "warnings" and not warnings:
            continue
        if show == "differs" and not daemon["differences"]:
            continue
        if show == "restart" and not daemon["restart_pending"]:
            continue
        try:
            checked_at = datetime.fromisoformat(str(check.get("at"))) if check.get("at") else None
        except ValueError:
            checked_at = None
        rows.append(
            _item(
                m,
                groups,
                str(m.id),
                {
                    "version": facts.get("version") or "",
                    "storage_driver": facts.get("storage_driver") or "",
                    "logging_driver": facts.get("logging_driver") or "",
                    "live_restore": facts.get("live_restore"),
                    "containers": facts.get("containers"),
                    "running": facts.get("running"),
                    "warnings": warnings,
                    "findings": len(check.get("findings") or []),
                    "check_error": check.get("error"),
                    "checked_at": checked_at,
                    "daemon": daemon,
                    "self_host": m.id in own,
                },
                is_own=m.id in own,
            )
        )
    return rows


async def _jobs(
    db: AsyncSession, user: User, flt: FleetListFilter, groups_of: dict[uuid.UUID, str]
) -> list[FleetItem]:
    visible = (await machines_visible_to(db, user)).with_only_columns(Machine.id)
    if flt.group_id is not None:
        visible = visible.where(Machine.group_id == flt.group_id)
    query = select(DockerJob, Machine).join(Machine, Machine.id == DockerJob.machine_id).where(
        DockerJob.machine_id.in_(visible.scalar_subquery())
    )
    if flt.show == "active":
        query = query.where(
            DockerJob.status.in_((DockerJobStatus.PENDING, DockerJobStatus.RUNNING))
        )
    elif flt.show == "failed":
        query = query.where(DockerJob.status == DockerJobStatus.FAILED)
    if flt.q:
        like = f"%{flt.q.lower()}%"
        query = query.where(
            DockerJob.target.ilike(like) | DockerJob.kind.ilike(like) | Machine.name.ilike(like)
        )
    result = await db.execute(query.order_by(DockerJob.created_at.desc()).limit(JOBS_LIMIT))
    rows: list[FleetItem] = []
    for job, m in result.all():
        rows.append(
            FleetItem(
                machine_id=m.id,
                machine_name=m.name,
                machine_ready=bool(m.host_key_fingerprint),
                group_name=groups_of.get(m.group_id) if m.group_id else None,
                ident=str(job.id),
                item={"job": job},
            )
        )
    return rows


def _matches(row: FleetItem, needle: str) -> bool:
    item = row.item
    return needle in _text(
        row.machine_name,
        row.group_name,
        row.ident,
        item.get("name"),
        item.get("ref"),
        item.get("driver"),
        item.get("compose_project"),
        item.get("repository"),
        item.get("version"),
        " ".join(item.get("used_by") or []),
        " ".join(item.get("containers") or []) if isinstance(item.get("containers"), list) else "",
    )


async def list_items(
    db: AsyncSession,
    user: User,
    kind: str,
    flt: FleetListFilter,
    *,
    settings: AppSettings | None = None,
    paged: bool = True,
) -> FleetList:
    machines = await docker_machines(db, user, flt.group_id)
    groups = await _group_names(db, machines)
    if kind == "jobs":
        all_groups = {
            row[0]: row[1]
            for row in (await db.execute(select(MachineGroup.id, MachineGroup.name))).all()
        }
        rows = await _jobs(db, user, flt, all_groups)
    elif kind == "stacks":
        rows = await _stacks(db, machines, groups, flt.show)
    elif kind == "images":
        rows = _images(machines, groups, flt.show)
    elif kind == "volumes":
        rows = _volumes(machines, groups, flt.show)
    elif kind == "networks":
        rows = _networks(machines, groups, flt.show)
    elif kind == "backups":
        rows = await _backups(db, machines, groups, flt.show)
    elif kind == "hosts":
        if settings is None:
            raise ValueError("hosts needs the app settings")
        rows = await _hosts(db, machines, groups, flt.show, settings)
    else:
        raise ValueError(kind)
    truncated = len(rows) > MAX_ROWS
    rows = rows[:MAX_ROWS]
    if flt.q and kind != "jobs":
        needle = flt.q.lower()
        rows = [r for r in rows if _matches(r, needle)]
    listed = {r.machine_id for r in rows}
    oldest: datetime | None = None
    never = 0
    if kind in ("images", "volumes", "networks", "stacks"):
        for m in machines:
            read = snapshot.read_at(m)
            if read is None:
                never += 1
            elif m.id in listed and (oldest is None or read < oldest):
                oldest = read
    if not paged:
        return FleetList(kind=kind, rows=rows, total=len(rows), machines=len(listed))
    pages = max(1, -(-len(rows) // PAGE_SIZE))
    page = min(flt.page, pages)
    return FleetList(
        kind=kind,
        rows=rows[(page - 1) * PAGE_SIZE : page * PAGE_SIZE],
        total=len(rows),
        page=page,
        pages=pages,
        machines=len(listed),
        truncated=truncated,
        oldest_read=oldest,
        never_read=never,
    )
