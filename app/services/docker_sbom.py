"""The packages inside Docker images (their SBOM), from Trivy's package
list with every image scan (`app.ssh.docker_scan`), kept one per row
(`DockerImagePackage`) and replaced with the scan.

- **Fleet-wide search** (Security → Package search, "In container
  images"): which images on which machines carry a package, and in which
  version - also for a vulnerability without a CVE, or before a scanner
  knows about it. Searched by name prefix in lower case, through an index.
- **CycloneDX download** of one image's packages (`cyclonedx`), for tools
  that take an SBOM.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Select, delete, func, insert, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.version import APP_VERSION
from app.db.models.docker import DockerImagePackage, DockerImageScan
from app.db.models.machine import Machine

SEARCH_LIMIT = 500
MIN_QUERY = 2
_BATCH = 1000


async def replace_packages(
    db: AsyncSession, scan: DockerImageScan, packages: list[dict[str, str]]
) -> None:
    """Put the scan's packages in place of the ones it had. Does not commit."""
    await db.execute(delete(DockerImagePackage).where(DockerImagePackage.scan_id == scan.id))
    rows = [
        {
            "scan_id": scan.id,
            "machine_id": scan.machine_id,
            "name": p["name"][:255],
            "name_key": p["name"][:255].lower(),
            "version": p.get("version", "")[:128],
            "type": p.get("type", "")[:32],
            "purl": p.get("purl", "")[:512],
        }
        for p in packages
    ]
    for start in range(0, len(rows), _BATCH):
        await db.execute(insert(DockerImagePackage), rows[start : start + _BATCH])


async def packages_of(db: AsyncSession, scan: DockerImageScan) -> list[DockerImagePackage]:
    result = await db.execute(
        select(DockerImagePackage)
        .where(DockerImagePackage.scan_id == scan.id)
        .order_by(DockerImagePackage.name_key, DockerImagePackage.version)
    )
    return list(result.scalars().all())


async def type_counts(db: AsyncSession, scan: DockerImageScan) -> dict[str, int]:
    """{"debian": 92, "python-pkg": 14, ...}, most first."""
    result = await db.execute(
        select(DockerImagePackage.type, func.count())
        .where(DockerImagePackage.scan_id == scan.id)
        .group_by(DockerImagePackage.type)
    )
    counts = {str(kind or "other"): int(n) for kind, n in result.all()}
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


@dataclass(frozen=True)
class Hit:
    machine: Machine
    image_id: str
    image_ref: str
    name: str
    version: str
    type: str


def _like_prefix(query: str) -> str:
    escaped = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"{escaped}%"


async def search(
    db: AsyncSession, visible_machine_ids: Select[Any], query: str
) -> tuple[list[Hit], bool]:
    """Packages whose name starts with `query` (case-insensitive) in the
    images of the machines `visible_machine_ids` selects. Returns (hits,
    truncated)."""
    needle = query.strip().lower()
    if len(needle) < MIN_QUERY:
        return [], False
    result = await db.execute(
        select(DockerImagePackage, DockerImageScan.image_id, DockerImageScan.image_ref, Machine)
        .join(DockerImageScan, DockerImageScan.id == DockerImagePackage.scan_id)
        .join(Machine, Machine.id == DockerImagePackage.machine_id)
        .where(
            DockerImagePackage.name_key.like(_like_prefix(needle[:255]), escape="\\"),
            DockerImagePackage.machine_id.in_(visible_machine_ids),
        )
        .order_by(DockerImagePackage.name_key, DockerImagePackage.version, Machine.name)
        .limit(SEARCH_LIMIT + 1)
    )
    hits = [
        Hit(
            machine=machine,
            image_id=image_id,
            image_ref=image_ref,
            name=package.name,
            version=package.version,
            type=package.type,
        )
        for package, image_id, image_ref, machine in result.all()
    ]
    return hits[:SEARCH_LIMIT], len(hits) > SEARCH_LIMIT


def hit_as_dict(hit: Hit) -> dict[str, Any]:
    return {
        "machine_id": str(hit.machine.id),
        "machine": hit.machine.name,
        "image_id": hit.image_id,
        "image": hit.image_ref,
        "name": hit.name,
        "version": hit.version,
        "type": hit.type,
    }


def cyclonedx(
    machine: Machine, scan: DockerImageScan, packages: list[DockerImagePackage]
) -> dict[str, Any]:
    """The image's packages as a CycloneDX 1.6 JSON document."""
    image = scan.image_ref or scan.image_id
    components: list[dict[str, Any]] = []
    for index, package in enumerate(packages):
        component: dict[str, Any] = {
            "type": "library",
            "bom-ref": f"pkg-{index}",
            "name": package.name,
        }
        if package.version:
            component["version"] = package.version
        if package.purl:
            component["purl"] = package.purl
        if package.type:
            component["properties"] = [{"name": "debcontrol:package_type", "value": package.type}]
        components.append(component)
    scanned = scan.scanned_at
    if scanned is not None and scanned.tzinfo is None:
        scanned = scanned.replace(tzinfo=UTC)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": (scanned or datetime.now(UTC)).isoformat(),
            "tools": {
                "components": [
                    {"type": "application", "name": "debcontrol", "version": APP_VERSION},
                    *(
                        [{"type": "application", "name": "trivy", "version": version}]
                        if (version := (scan.scanners or {}).get("trivy"))
                        else []
                    ),
                ]
            },
            "component": {
                "type": "container",
                "bom-ref": "image",
                "name": image,
                "version": scan.image_id,
                "properties": [{"name": "debcontrol:machine", "value": machine.name}],
            },
        },
        "components": components,
    }


def filename(scan: DockerImageScan) -> str:
    """A safe download name: `nginx_1.27-sbom.cdx.json`."""
    base = (scan.image_ref or scan.image_id).rsplit("/", 1)[-1]
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in base)[:100] or "image"
    return f"{safe}-sbom.cdx.json"
