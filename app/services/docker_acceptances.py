"""Accepted container vulnerabilities, and the fleet-wide view of the
critical and high ones (Security → Container vulnerabilities).

An admin can accept a critical or high vulnerability — for every image,
or for one image repository (`repository_key`, e.g.
"docker.io/library/nginx") — until a date (`MAX_DAYS` at most). Until
then it is left out of each scan's counts (`DockerImageScan.counts`; what
the scanners found stays in `raw_counts`), so the vulnerability gate, the
machine's summary, the vulnerability conditions in notification rules and
every count on the Docker tab no longer see it. The per-image list still
shows it, marked accepted. When the date passes, the hourly expiry
(`expire`) removes the acceptance and the counts include it again.

Only critical and high findings can be accepted: they are the ones the
gate and the alerts look at, and the ones kept in `DockerImageFinding`
to find every scan a vulnerability is in.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.docker import (
    DockerImageFinding,
    DockerImageScan,
    DockerVulnerabilityAcceptance,
)
from app.db.models.machine import Machine
from app.services.image_versions import parse_image

SERIOUS: tuple[str, ...] = ("critical", "high")
DEFAULT_DAYS = 90
MAX_DAYS = 365
MAX_REASON = 500
# How many rows the fleet list shows at most.
FLEET_LIMIT = 500


def repository_key(image_ref: str) -> str:
    """The repository an image reference belongs to, the same for every
    tag of it (`nginx:1.27` and `docker.io/library/nginx:1.28` ->
    "docker.io/library/nginx")."""
    parsed = parse_image(image_ref)
    if parsed is not None:
        return f"{parsed.registry}/{parsed.repository}"[:512]
    name = image_ref.split("@", 1)[0]
    if ":" in name.rsplit("/", 1)[-1]:
        name = name.rsplit(":", 1)[0]
    return name[:512]


def is_vuln_id_valid(value: str) -> bool:
    """CVE-…, GHSA-…, a distribution's own id: letters, digits and `-._:`."""
    return 0 < len(value) <= 128 and all(
        (c.isascii() and c.isalnum()) or c in "-._:" for c in value
    )


def _aware(when: datetime) -> datetime:
    return when if when.tzinfo is not None else when.replace(tzinfo=UTC)


async def active(db: AsyncSession) -> list[DockerVulnerabilityAcceptance]:
    now = datetime.now(UTC)
    result = await db.execute(
        select(DockerVulnerabilityAcceptance)
        .where(DockerVulnerabilityAcceptance.expires_at > now)
        .order_by(DockerVulnerabilityAcceptance.vuln_id)
    )
    return list(result.scalars().all())


def accepted_ids(acceptances: list[DockerVulnerabilityAcceptance], image_ref: str) -> set[str]:
    """The vulnerability ids accepted for an image."""
    key = repository_key(image_ref) if image_ref else ""
    now = datetime.now(UTC)
    return {
        a.vuln_id
        for a in acceptances
        if (not a.image or a.image == key) and _aware(a.expires_at) > now
    }


def accepted_for(
    acceptances: list[DockerVulnerabilityAcceptance], image_ref: str
) -> dict[str, DockerVulnerabilityAcceptance]:
    """`{vuln_id: acceptance}` for an image (the per-image list's badges)."""
    key = repository_key(image_ref) if image_ref else ""
    found: dict[str, DockerVulnerabilityAcceptance] = {}
    for a in acceptances:
        # One for this image wins over one for every image.
        if (not a.image or a.image == key) and (a.vuln_id not in found or a.image):
            found[a.vuln_id] = a
    return found


def apply(scan: DockerImageScan, acceptances: list[DockerVulnerabilityAcceptance]) -> bool:
    """Recompute the scan's counts without its accepted critical and high
    findings. True when they changed."""
    raw = dict(scan.raw_counts or scan.counts or {})
    if not raw:
        return False
    accepted = accepted_ids(acceptances, scan.image_ref)
    effective = dict(raw)
    # Each finding (one vulnerability in one package) is counted once.
    for item in scan.vulnerabilities or []:
        if not isinstance(item, dict):
            continue
        vuln_id, severity = str(item.get("id") or ""), str(item.get("severity") or "")
        if severity in SERIOUS and vuln_id in accepted:
            effective[severity] = max(0, int(effective.get(severity, 0)) - 1)
    changed = effective != (scan.counts or {})
    scan.raw_counts = raw if effective != raw else None
    scan.counts = effective
    return changed


def findings_of(scan: DockerImageScan) -> list[DockerImageFinding]:
    """The scan's critical and high findings, as rows of their own."""
    rows: list[DockerImageFinding] = []
    for item in scan.vulnerabilities or []:
        if not isinstance(item, dict) or item.get("severity") not in SERIOUS:
            continue
        vuln_id = str(item.get("id") or "")[:128]
        if not vuln_id:
            continue
        rows.append(
            DockerImageFinding(
                scan_id=scan.id,
                machine_id=scan.machine_id,
                vuln_id=vuln_id,
                severity=str(item["severity"]),
                pkg=str(item.get("pkg") or "")[:255],
                installed=str(item.get("installed") or "")[:128],
                fixed=str(item.get("fixed") or "")[:255],
            )
        )
    return rows


async def replace_findings(db: AsyncSession, scan: DockerImageScan) -> None:
    """Keep the findings table in step with a (re)stored scan. Does not
    commit; the scan must have been flushed (it needs its id)."""
    await db.execute(delete(DockerImageFinding).where(DockerImageFinding.scan_id == scan.id))
    db.add_all(findings_of(scan))


async def recompute(db: AsyncSession, vuln_ids: set[str]) -> int:
    """Re-apply the acceptances to every scan holding one of `vuln_ids`,
    and refresh those machines' summaries. Returns the scans changed. Does
    not commit."""
    from app.services import docker_scans

    if not vuln_ids:
        return 0
    scan_ids = select(DockerImageFinding.scan_id).where(
        DockerImageFinding.vuln_id.in_(sorted(vuln_ids))
    )
    result = await db.execute(select(DockerImageScan).where(DockerImageScan.id.in_(scan_ids)))
    scans = list(result.scalars().all())
    acceptances = await active(db)
    machines: set[uuid.UUID] = set()
    changed = 0
    for scan in scans:
        if apply(scan, acceptances):
            changed += 1
            machines.add(scan.machine_id)
    await db.flush()
    for machine_id in machines:
        machine = await db.get(Machine, machine_id)
        if machine is not None:
            await docker_scans.summarize(db, machine, None)
    return changed


async def accept(
    db: AsyncSession,
    *,
    vuln_id: str,
    image: str,
    reason: str,
    days: int,
    actor: str | None,
) -> DockerVulnerabilityAcceptance:
    """Accept (or extend) a vulnerability; `image` "" = every image, else
    an image reference or repository (`repository_key`). Does not commit;
    the counts follow in the background (`app.tasks.docker_jobs.
    recompute_vulnerability_acceptances`)."""
    if not is_vuln_id_valid(vuln_id):
        raise ValueError("Invalid vulnerability id.")
    days = max(1, min(int(days), MAX_DAYS))
    key = repository_key(image.strip()) if image.strip() else ""
    result = await db.execute(
        select(DockerVulnerabilityAcceptance).where(
            DockerVulnerabilityAcceptance.vuln_id == vuln_id,
            DockerVulnerabilityAcceptance.image == key,
        )
    )
    row = result.scalar_one_or_none()
    if row is None:
        row = DockerVulnerabilityAcceptance(vuln_id=vuln_id, image=key)
        db.add(row)
    row.reason = reason.strip()[:MAX_REASON]
    row.expires_at = datetime.now(UTC) + timedelta(days=days)
    row.created_by = actor
    row.created_at = datetime.now(UTC)
    await db.flush()
    return row


async def expire(db: AsyncSession) -> int:
    """Remove the acceptances whose date has passed and count their
    vulnerabilities again. Returns how many expired. Does not commit."""
    now = datetime.now(UTC)
    result = await db.execute(
        select(DockerVulnerabilityAcceptance).where(
            DockerVulnerabilityAcceptance.expires_at <= now
        )
    )
    expired = list(result.scalars().all())
    if not expired:
        return 0
    vuln_ids = {a.vuln_id for a in expired}
    for row in expired:
        await db.delete(row)
    await db.flush()
    await recompute(db, vuln_ids)
    return len(expired)


@dataclass
class FleetRow:
    vuln_id: str
    severity: str
    machines: int
    images: int
    fixable: bool
    accepted: bool


async def fleet_overview(
    db: AsyncSession, visible_machine_ids: Any, *, query: str = ""
) -> tuple[list[FleetRow], bool]:
    """Every critical and high vulnerability in the stored scans of the
    machines in `visible_machine_ids` (a select of machine ids), with how
    many machines and images have it. Most severe and widespread first.
    Returns (rows, truncated)."""
    stmt = (
        select(
            DockerImageFinding.vuln_id,
            func.min(DockerImageFinding.severity),
            func.count(func.distinct(DockerImageFinding.machine_id)),
            func.count(func.distinct(DockerImageFinding.scan_id)),
            func.max(DockerImageFinding.fixed),
        )
        .where(DockerImageFinding.machine_id.in_(visible_machine_ids))
        .group_by(DockerImageFinding.vuln_id)
    )
    if query.strip():
        needle = query.strip()[:128]
        stmt = stmt.where(
            DockerImageFinding.vuln_id.ilike(f"%{needle}%")
            | DockerImageFinding.pkg.ilike(f"%{needle}%")
        )
    # "critical" < "high" alphabetically, so min() is the most severe.
    stmt = stmt.order_by(
        func.min(DockerImageFinding.severity),
        func.count(func.distinct(DockerImageFinding.machine_id)).desc(),
        DockerImageFinding.vuln_id,
    ).limit(FLEET_LIMIT + 1)
    rows = (await db.execute(stmt)).all()
    accepted = {a.vuln_id for a in await active(db)}
    result = [
        FleetRow(
            vuln_id=str(vuln_id),
            severity=str(severity),
            machines=int(machines),
            images=int(images),
            fixable=bool(fixed),
            accepted=str(vuln_id) in accepted,
        )
        for vuln_id, severity, machines, images, fixed in rows[:FLEET_LIMIT]
    ]
    return result, len(rows) > FLEET_LIMIT


@dataclass
class Occurrence:
    machine: Machine
    image_ref: str
    image_id: str
    severity: str
    pkg: str
    installed: str
    fixed: str


async def occurrences(
    db: AsyncSession, vuln_id: str, visible_machine_ids: Any
) -> list[Occurrence]:
    """Where one vulnerability is: each machine, image and package."""
    stmt = (
        select(DockerImageFinding, DockerImageScan, Machine)
        .join(DockerImageScan, DockerImageScan.id == DockerImageFinding.scan_id)
        .join(Machine, Machine.id == DockerImageFinding.machine_id)
        .where(
            DockerImageFinding.vuln_id == vuln_id,
            DockerImageFinding.machine_id.in_(visible_machine_ids),
        )
        .order_by(Machine.name, DockerImageScan.image_ref, DockerImageFinding.pkg)
        .limit(FLEET_LIMIT)
    )
    return [
        Occurrence(
            machine=machine,
            image_ref=scan.image_ref,
            image_id=scan.image_id,
            severity=finding.severity,
            pkg=finding.pkg,
            installed=finding.installed,
            fixed=finding.fixed,
        )
        for finding, scan, machine in (await db.execute(stmt)).all()
    ]
