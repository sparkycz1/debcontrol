"""Every container of the visible fleet in one list (Docker → Containers):
the latest monitoring sample of each machine, with its image update state
and vulnerability counts, filtered, sorted and paged here so the web page
and `GET /api/v1/docker/containers` answer the same.

It reads what the machines already reported (`Machine.docker_containers`,
`docker_image_updates`, the stored scans); nothing is asked over SSH.
Only machines whose Docker was readable at the last sample are included.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import exists, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.docker import DockerContainerSetting, DockerImageScan
from app.db.models.machine import Machine
from app.db.models.machine_group import MachineGroup
from app.db.models.user import User
from app.services import docker_overview
from app.services.access_scope import machines_visible_to

PAGE_SIZE = 100
# A guard for very large fleets: the list stops here and says so.
MAX_CONTAINERS = 20_000
SORTS = ("machine", "name", "image", "state", "vulns", "update")
VULN_FILTERS = ("critical", "high")


@dataclass(frozen=True)
class FleetFilter:
    q: str = ""
    state: str = ""
    group_id: uuid.UUID | None = None
    update: bool = False
    vulns: str = ""
    stack: str = ""
    sort: str = "machine"
    desc: bool = False
    page: int = 1

    @classmethod
    def parse(
        cls,
        *,
        q: str = "",
        state: str = "",
        group: str = "",
        update: str = "",
        vulns: str = "",
        stack: str = "",
        sort: str = "",
        desc: str = "",
        page: int = 1,
    ) -> FleetFilter:
        try:
            group_id = uuid.UUID(group) if group else None
        except ValueError:
            group_id = None
        return cls(
            q=q.strip()[:200],
            state=state if state in docker_overview.STATE_GROUPS else "",
            group_id=group_id,
            update=update in ("1", "true", "on"),
            vulns=vulns if vulns in VULN_FILTERS else "",
            stack=stack.strip()[:255],
            sort=sort if sort in SORTS else "machine",
            desc=desc in ("1", "true", "on"),
            page=max(1, page),
        )


@dataclass
class FleetRow:
    machine_id: uuid.UUID
    machine_name: str
    machine_ready: bool
    group_name: str | None
    container: dict[str, Any]
    row_state: str
    image_status: str | None
    image_id: str | None
    counts: dict[str, int] | None
    auto_update: bool
    web_links: list[dict[str, Any]]

    @property
    def name(self) -> str:
        return str(self.container.get("name") or "")

    @property
    def key(self) -> str:
        """The value a row's checkbox submits: `<machine id>/<container>`."""
        return f"{self.machine_id}/{self.name}"


@dataclass
class FleetPage:
    rows: list[FleetRow] = field(default_factory=list)
    total: int = 0
    page: int = 1
    pages: int = 1
    # Counts per state group over the rows matching every other filter.
    state_counts: dict[str, int] = field(default_factory=dict)
    machines: int = 0
    with_update: int = 0
    truncated: bool = False


def _severity_rank(counts: dict[str, int] | None) -> int:
    if not counts:
        return -1
    return (
        int(counts.get("critical", 0)) * 1_000_000
        + int(counts.get("high", 0)) * 1_000
        + int(counts.get("medium", 0))
    )


async def _scans(
    db: AsyncSession, machine_ids: list[uuid.UUID]
) -> dict[tuple[uuid.UUID, str], tuple[str, dict[str, int] | None]]:
    """`(machine id, image ref) → (image id, counts)` of the stored scans —
    only the small columns, never the vulnerability lists."""
    found: dict[tuple[uuid.UUID, str], tuple[str, dict[str, int] | None]] = {}
    for start in range(0, len(machine_ids), 500):
        chunk = machine_ids[start : start + 500]
        result = await db.execute(
            select(
                DockerImageScan.machine_id,
                DockerImageScan.image_ref,
                DockerImageScan.image_id,
                DockerImageScan.counts,
            ).where(DockerImageScan.machine_id.in_(chunk))
        )
        for machine_id, ref, image_id, counts in result.all():
            if ref:
                found[(machine_id, ref)] = (image_id, counts)
    return found


async def _auto_update(
    db: AsyncSession, machine_ids: list[uuid.UUID]
) -> set[tuple[uuid.UUID, str]]:
    found: set[tuple[uuid.UUID, str]] = set()
    for start in range(0, len(machine_ids), 500):
        chunk = machine_ids[start : start + 500]
        result = await db.execute(
            select(DockerContainerSetting.machine_id, DockerContainerSetting.name).where(
                DockerContainerSetting.machine_id.in_(chunk), DockerContainerSetting.auto_update
            )
        )
        found.update((m, n) for m, n in result.all())
    return found


def _matches_text(row: FleetRow, needle: str) -> bool:
    c = row.container
    haystack = (
        row.machine_name,
        row.name,
        str(c.get("image") or ""),
        str(c.get("compose_project") or ""),
        str(c.get("ports") or ""),
        row.group_name or "",
    )
    return any(needle in value.lower() for value in haystack)


async def all_rows(db: AsyncSession, user: User) -> tuple[list[FleetRow], bool]:
    """Every container of every visible machine with readable Docker, and
    whether the list stopped at `MAX_CONTAINERS`."""
    query = (await machines_visible_to(db, user)).where(Machine.docker_status == "ok")
    query = query.with_only_columns(
        Machine.id,
        Machine.name,
        Machine.ip_address,
        Machine.host_key_fingerprint,
        Machine.group_id,
        Machine.docker_containers,
        Machine.docker_image_updates,
        maintain_column_froms=True,
    ).order_by(Machine.name)
    machines = (await db.execute(query)).all()
    group_ids = {m.group_id for m in machines if m.group_id is not None}
    groups: dict[uuid.UUID, str] = {}
    if group_ids:
        result = await db.execute(
            select(MachineGroup.id, MachineGroup.name).where(MachineGroup.id.in_(group_ids))
        )
        groups = {row[0]: row[1] for row in result.all()}
    ids = [m.id for m in machines]
    scans = await _scans(db, ids)
    auto = await _auto_update(db, ids)
    rows: list[FleetRow] = []
    truncated = False
    for m in machines:
        updates = m.docker_image_updates or {}
        for container in m.docker_containers or []:
            if not isinstance(container, dict) or not container.get("name"):
                continue
            if len(rows) >= MAX_CONTAINERS:
                truncated = True
                break
            image = str(container.get("image") or "")
            scan = scans.get((m.id, image))
            rows.append(
                FleetRow(
                    machine_id=m.id,
                    machine_name=m.name,
                    machine_ready=bool(m.host_key_fingerprint),
                    group_name=groups.get(m.group_id) if m.group_id else None,
                    container=container,
                    row_state=docker_overview.row_state(container),
                    image_status=updates.get(image) if isinstance(updates, dict) else None,
                    image_id=scan[0] if scan else None,
                    counts=scan[1] if scan else None,
                    auto_update=(m.id, str(container.get("name"))) in auto,
                    web_links=docker_overview.links_of(container, m.ip_address),
                )
            )
        if truncated:
            break
    return rows, truncated


def _sort_key(sort: str) -> Any:
    if sort == "name":
        return lambda r: (r.name.lower(), r.machine_name.lower())
    if sort == "image":
        return lambda r: (str(r.container.get("image") or "").lower(), r.machine_name.lower())
    if sort == "state":
        order = {s: i for i, s in enumerate(docker_overview.STATE_GROUPS)}
        return lambda r: (order.get(r.row_state, 99), r.machine_name.lower(), r.name.lower())
    if sort == "vulns":
        return lambda r: (_severity_rank(r.counts), r.machine_name.lower(), r.name.lower())
    if sort == "update":
        return lambda r: (r.image_status == "update", r.machine_name.lower(), r.name.lower())
    return lambda r: (r.machine_name.lower(), r.name.lower())


async def list_containers(db: AsyncSession, user: User, flt: FleetFilter) -> FleetPage:
    rows, truncated = await all_rows(db, user)
    needle = flt.q.lower()

    def keep(row: FleetRow, *, ignore_state: bool = False) -> bool:
        if needle and not _matches_text(row, needle):
            return False
        if flt.stack and str(row.container.get("compose_project") or "") != flt.stack:
            return False
        if flt.update and row.image_status != "update":
            return False
        if flt.vulns == "critical" and not (row.counts or {}).get("critical"):
            return False
        if flt.vulns == "high" and not (
            (row.counts or {}).get("critical") or (row.counts or {}).get("high")
        ):
            return False
        return ignore_state or not flt.state or row.row_state == flt.state

    if flt.group_id is not None:
        group_machines = set(
            (
                await db.execute(select(Machine.id).where(Machine.group_id == flt.group_id))
            ).scalars()
        )
        rows = [r for r in rows if r.machine_id in group_machines]
    base = [r for r in rows if keep(r, ignore_state=True)]
    counts = dict.fromkeys(docker_overview.STATE_GROUPS, 0)
    for row in base:
        counts[row.row_state] = counts.get(row.row_state, 0) + 1
    matching = [r for r in base if not flt.state or r.row_state == flt.state]
    matching.sort(key=_sort_key(flt.sort), reverse=flt.desc)
    pages = max(1, -(-len(matching) // PAGE_SIZE))
    page = min(flt.page, pages)
    return FleetPage(
        rows=matching[(page - 1) * PAGE_SIZE : page * PAGE_SIZE],
        total=len(matching),
        page=page,
        pages=pages,
        state_counts=counts,
        machines=len({r.machine_id for r in matching}),
        with_update=sum(1 for r in matching if r.image_status == "update"),
        truncated=truncated,
    )


def parse_keys(values: list[str]) -> dict[uuid.UUID, list[str]]:
    """Checkbox values `<machine id>/<container>` → `{machine id: [names]}`,
    invalid ones dropped (the names are validated again by the action)."""
    grouped: dict[uuid.UUID, list[str]] = {}
    for value in values:
        machine_part, sep, name = value.partition("/")
        if not sep or not name:
            continue
        try:
            machine_id = uuid.UUID(machine_part)
        except ValueError:
            continue
        grouped.setdefault(machine_id, [])
        if name not in grouped[machine_id]:
            grouped[machine_id].append(name)
    return grouped


# Whether the header shows the Docker entry: some machine reported Docker.
# Read on every page render, so cached in process for a minute.
_PRESENCE_TTL_SECONDS = 60.0
_presence_cache: tuple[float, bool] | None = None


async def fleet_has_docker(db: AsyncSession) -> bool:
    global _presence_cache
    now = time.monotonic()
    if _presence_cache is not None and now - _presence_cache[0] < _PRESENCE_TTL_SECONDS:
        return _presence_cache[1]
    present = bool(
        (
            await db.execute(select(exists().where(Machine.docker_status.is_not(None))))
        ).scalar()
    )
    _presence_cache = (now, present)
    return present


def reset_presence_cache() -> None:
    global _presence_cache
    _presence_cache = None
