"""The fleet-wide view of pending apt security updates — `GET
/machines/security-updates` and `GET /api/v1/machines/security-updates`:
one row per (package, new version), with the CVEs it fixes, its changelog
urgency and every visible machine it's pending on, most urgent first.

Built from each machine's stored `apt_upgradable_packages` (refreshed by
every update check, see `app.ssh.updates` / `app.ssh.security_advisories`),
so it costs one query over the machines that report a pending security
update — no SSH, no external lookup.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import Select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.machine import Machine
from app.ssh.security_advisories import cve_sort_key

_URGENCY_RANK = {"emergency": 5, "critical": 4, "high": 3, "medium": 2, "low": 1}


@dataclass
class SecurityUpdateRow:
    package: str
    new_version: str | None
    urgency: str | None
    # None = not looked up on any machine yet.
    cves: list[str] | None
    machines: list[Machine] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "new_version": self.new_version,
            "urgency": self.urgency,
            "cves": self.cves,
            "machines": [{"id": str(m.id), "name": m.name} for m in self.machines],
        }


def build_security_overview(machines: list[Machine]) -> list[SecurityUpdateRow]:
    """Pure: group every machine's pending security packages by (name,
    new version). CVE lists from different machines are merged; the most
    urgent urgency wins."""
    rows: dict[tuple[str, str | None], SecurityUpdateRow] = {}
    for machine in machines:
        for package in machine.apt_upgradable_packages or []:
            if not isinstance(package, dict) or not package.get("security"):
                continue
            name = str(package.get("name") or "")
            if not name:
                continue
            new_version = package.get("new_version")
            key = (name, str(new_version) if new_version else None)
            row = rows.get(key)
            if row is None:
                row = rows[key] = SecurityUpdateRow(
                    package=name, new_version=key[1], urgency=None, cves=None
                )
            if machine not in row.machines:
                row.machines.append(machine)
            cves = package.get("cves")
            if isinstance(cves, list):
                merged = set(row.cves or []) | {str(c) for c in cves}
                row.cves = sorted(merged, key=cve_sort_key, reverse=True)
            urgency = package.get("urgency")
            if isinstance(urgency, str) and _URGENCY_RANK.get(urgency, 0) > _URGENCY_RANK.get(
                row.urgency or "", 0
            ):
                row.urgency = urgency
    for row in rows.values():
        row.machines.sort(key=lambda m: m.name.lower())
    return sorted(
        rows.values(),
        key=lambda r: (
            -_URGENCY_RANK.get(r.urgency or "", 0),
            -len(r.cves or []),
            -len(r.machines),
            r.package,
        ),
    )


def machines_without_package_details(machines: list[Machine]) -> list[Machine]:
    """Pure: machines whose last check counted pending security updates but
    whose stored package list flags none of them — a list stored before
    per-package security flags existed (pre-0.75.0), which the next update
    check replaces. Shown on the page so the count elsewhere (Dashboard,
    Machines list) and this page's rows never silently disagree."""
    return sorted(
        (
            m
            for m in machines
            if m.security_upgradable_count
            and not any(
                isinstance(p, dict) and p.get("security")
                for p in (m.apt_upgradable_packages or [])
            )
        ),
        key=lambda m: m.name.lower(),
    )


async def _load_machines(db: AsyncSession, visible_machines: Select[Machine]) -> list[Machine]:
    result = await db.execute(
        visible_machines.where(Machine.is_active, Machine.security_upgradable_count > 0)
    )
    return list(result.scalars().all())


async def load_security_overview(
    db: AsyncSession, visible_machines: Select[Machine]
) -> list[SecurityUpdateRow]:
    """`visible_machines` is the caller's already access-scoped machine
    query (`app.services.access_scope.machines_visible_to`)."""
    return build_security_overview(await _load_machines(db, visible_machines))


async def load_security_overview_with_gaps(
    db: AsyncSession, visible_machines: Select[Machine]
) -> tuple[list[SecurityUpdateRow], list[Machine]]:
    """`load_security_overview` plus `machines_without_package_details`,
    from the same single query."""
    machines = await _load_machines(db, visible_machines)
    return build_security_overview(machines), machines_without_package_details(machines)
