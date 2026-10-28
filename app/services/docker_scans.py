"""Stored vulnerability scans (`DockerImageScan`) and the per-machine
summary kept on the machine (`Machine.docker_vulnerabilities`), which the
Docker tab, the machine list and notification conditions read.

A scan is stored per image id, so the same image is not scanned again
until it changes; scans of images that are gone from the machine are
dropped whenever the machine's images are read after a scan. Its counts
leave out accepted vulnerabilities (`app.services.docker_acceptances`),
and its critical and high findings are also kept one per row
(`DockerImageFinding`) for the fleet-wide view.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.docker import DockerImageScan
from app.db.models.machine import Machine
from app.ssh.docker_cli import is_image_id_valid
from app.ssh.docker_scan import SEVERITIES, ImageScanResult


async def scans_by_image(db: AsyncSession, machine_id: uuid.UUID) -> dict[str, DockerImageScan]:
    result = await db.execute(
        select(DockerImageScan).where(DockerImageScan.machine_id == machine_id)
    )
    return {row.image_id: row for row in result.scalars().all()}


async def get_scan(
    db: AsyncSession, machine_id: uuid.UUID, image_id: str
) -> DockerImageScan | None:
    result = await db.execute(
        select(DockerImageScan).where(
            DockerImageScan.machine_id == machine_id, DockerImageScan.image_id == image_id
        )
    )
    return result.scalar_one_or_none()


async def store(
    db: AsyncSession,
    machine_id: uuid.UUID,
    results: list[ImageScanResult],
    image_ids: dict[str, str],
) -> dict[str, dict[str, int] | None]:
    """Keep each successful scan under its image's id (`image_ids` maps the
    name a result was scanned as to that id). Returns the severity counts
    per image id — None for an image neither scanner could scan. Does not
    commit."""
    from app.services import docker_acceptances

    counts: dict[str, dict[str, int] | None] = {}
    existing = await scans_by_image(db, machine_id)
    acceptances = await docker_acceptances.active(db)
    stored: list[DockerImageScan] = []
    now = datetime.now(UTC)
    for result in results:
        image_id = image_ids.get(result.image) or (
            result.image if is_image_id_valid(result.image) else ""
        )
        if not image_id:
            continue
        if not result.ok:
            counts.setdefault(image_id, None)
            continue
        row = existing.get(image_id)
        if row is None:
            row = DockerImageScan(machine_id=machine_id, image_id=image_id)
            db.add(row)
            existing[image_id] = row
        row.image_ref = result.image[:512]
        row.scanners = dict(result.scanners)
        row.counts = dict(result.counts)
        row.raw_counts = None
        row.vulnerabilities = list(result.vulnerabilities)
        row.errors = dict(result.errors) or None
        row.scanned_at = now
        docker_acceptances.apply(row, acceptances)
        counts[image_id] = dict(row.counts or {})
        stored.append(row)
    await db.flush()
    for row in stored:
        await docker_acceptances.replace_findings(db, row)
    await db.flush()
    return counts


async def forget_missing(db: AsyncSession, machine_id: uuid.UUID, present: set[str]) -> None:
    """Drop the scans of images no longer on the machine. Does not commit."""
    if not present:
        return
    await db.execute(
        delete(DockerImageScan).where(
            DockerImageScan.machine_id == machine_id,
            DockerImageScan.image_id.not_in(present),
        )
    )


async def summarize(
    db: AsyncSession, machine: Machine, in_use: set[str] | None
) -> dict[str, Any]:
    """Recompute `machine.docker_vulnerabilities` over the images its
    containers use (`in_use`; when unknown, those of the previous summary,
    else every scanned image). Does not commit."""
    scans = await scans_by_image(db, machine.id)
    if in_use is None:
        previous = (machine.docker_vulnerabilities or {}).get("image_ids")
        in_use = {str(i) for i in previous} if isinstance(previous, list) else None
    images = in_use if in_use is not None else set(scans)
    totals = dict.fromkeys(SEVERITIES, 0)
    scanned = 0
    latest: datetime | None = None
    for image_id in images:
        scan = scans.get(image_id)
        if scan is None or scan.counts is None:
            continue
        scanned += 1
        for severity in SEVERITIES:
            totals[severity] += int((scan.counts or {}).get(severity, 0))
        when = scan.scanned_at
        if when is not None and when.tzinfo is None:
            when = when.replace(tzinfo=UTC)
        if when is not None and (latest is None or when > latest):
            latest = when
    summary: dict[str, Any] = {
        **totals,
        "images": scanned,
        "unscanned": len(images) - scanned,
        "scanned_at": latest.isoformat() if latest else None,
        # Which images were summed, to sum the same ones again when only
        # the counts changed (an accepted vulnerability).
        "image_ids": sorted(images),
    }
    machine.docker_vulnerabilities = summary
    return summary


def counts_of(scan: DockerImageScan | None) -> dict[str, int] | None:
    return dict(scan.counts) if scan is not None and scan.counts is not None else None
