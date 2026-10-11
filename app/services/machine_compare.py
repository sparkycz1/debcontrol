"""Two machines side by side — what differs between them in their facts,
installed packages and systemd services. For "why does this one behave
differently from that one": a package only one has, a different version,
a service running on one and not on the other, an extra listening port.

Everything is read from what is already stored (the last facts, packages
and services refresh of each machine); nothing is run on either machine.
Used by `GET /machines/compare` and `GET /api/v1/machines/compare`.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.machine import Machine
from app.db.models.machine_package import MachinePackage
from app.db.models.machine_service import MachineService
from app.services import config_drift

# Rows listed per section before the page says "and N more" — two machines
# on different releases differ in thousands of package versions.
MAX_ROWS = 500


@dataclass
class FactRow:
    name: str
    is_set: bool
    differs: bool
    # A plain fact: each machine's value.
    a: str | None = None
    b: str | None = None
    # A set-valued fact (disks, ports, accounts): what only one side has.
    only_a: list[str] = field(default_factory=list)
    only_b: list[str] = field(default_factory=list)
    common: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "field": self.name,
            "differs": self.differs,
            "a": self.a,
            "b": self.b,
            "only_a": self.only_a,
            "only_b": self.only_b,
        }


@dataclass
class ItemDiff:
    """One kind of thing both machines have a list of (packages, services)."""

    # (name, value on that machine)
    only_a: list[tuple[str, str]] = field(default_factory=list)
    only_b: list[tuple[str, str]] = field(default_factory=list)
    # (name, value on A, value on B)
    different: list[tuple[str, str, str]] = field(default_factory=list)
    same: int = 0

    @property
    def differences(self) -> int:
        return len(self.only_a) + len(self.only_b) + len(self.different)

    def as_dict(self) -> dict[str, Any]:
        return {
            "same": self.same,
            "only_a": [{"name": n, "value": v} for n, v in self.only_a],
            "only_b": [{"name": n, "value": v} for n, v in self.only_b],
            "different": [{"name": n, "a": a, "b": b} for n, a, b in self.different],
        }


@dataclass
class Comparison:
    a: Machine
    b: Machine
    facts: list[FactRow]
    packages: ItemDiff
    services: ItemDiff
    # Neither refresh has run on one of the machines yet: an empty side then
    # means "unknown", not "has nothing".
    packages_known: bool
    services_known: bool


def diff_items(a: dict[str, str], b: dict[str, str]) -> ItemDiff:
    """What differs between two name → value maps. Pure function."""
    result = ItemDiff()
    for name in sorted(a.keys() | b.keys()):
        if name not in b:
            result.only_a.append((name, a[name]))
        elif name not in a:
            result.only_b.append((name, b[name]))
        elif a[name] != b[name]:
            result.different.append((name, a[name], b[name]))
        else:
            result.same += 1
    return result


def diff_facts(a: Machine, b: Machine) -> list[FactRow]:
    """The tracked facts (`config_drift.TRACKED_FIELDS`) of both machines,
    in that order, each marked as differing or not. A fact unknown on one
    side is not a difference."""
    snapshot_a, snapshot_b = config_drift.snapshot(a), config_drift.snapshot(b)
    rows: list[FactRow] = []
    for name, (_label, is_set) in config_drift.TRACKED_FIELDS.items():
        value_a, value_b = snapshot_a.get(name), snapshot_b.get(name)
        if is_set:
            set_a = value_a if isinstance(value_a, frozenset) else None
            set_b = value_b if isinstance(value_b, frozenset) else None
            known = set_a is not None and set_b is not None
            only_a = sorted((set_a or frozenset()) - (set_b or frozenset())) if known else []
            only_b = sorted((set_b or frozenset()) - (set_a or frozenset())) if known else []
            rows.append(
                FactRow(
                    name=name,
                    is_set=True,
                    differs=bool(only_a or only_b),
                    only_a=only_a,
                    only_b=only_b,
                    common=len((set_a or frozenset()) & (set_b or frozenset())),
                )
            )
        else:
            text_a = value_a if isinstance(value_a, str) else None
            text_b = value_b if isinstance(value_b, str) else None
            rows.append(
                FactRow(
                    name=name,
                    is_set=False,
                    differs=text_a is not None and text_b is not None and text_a != text_b,
                    a=text_a,
                    b=text_b,
                )
            )
    return rows


async def _packages(db: AsyncSession, machine_id: uuid.UUID) -> dict[str, str]:
    result = await db.execute(
        select(MachinePackage.source, MachinePackage.name, MachinePackage.version).where(
            MachinePackage.machine_id == machine_id
        )
    )
    # apt packages by their bare name; flatpak/snap ones prefixed, so the
    # same name from two sources is two things.
    return {
        (name if source.value == "apt" else f"{source.value}:{name}"): version
        for source, name, version in result.all()
    }


async def _services(db: AsyncSession, machine_id: uuid.UUID) -> dict[str, str]:
    result = await db.execute(
        select(MachineService.unit, MachineService.active_state, MachineService.sub_state).where(
            MachineService.machine_id == machine_id
        )
    )
    return {unit: f"{active} ({sub})" for unit, active, sub in result.all()}


async def compare(db: AsyncSession, a: Machine, b: Machine) -> Comparison:
    """`a` and `b` must already be access-checked by the caller."""
    return Comparison(
        a=a,
        b=b,
        facts=diff_facts(a, b),
        packages=diff_items(await _packages(db, a.id), await _packages(db, b.id)),
        services=diff_items(await _services(db, a.id), await _services(db, b.id)),
        packages_known=a.packages_updated_at is not None and b.packages_updated_at is not None,
        services_known=a.services_updated_at is not None and b.services_updated_at is not None,
    )


def as_dict(comparison: Comparison) -> dict[str, Any]:
    return {
        "a": {"id": str(comparison.a.id), "name": comparison.a.name},
        "b": {"id": str(comparison.b.id), "name": comparison.b.name},
        "facts": [row.as_dict() for row in comparison.facts],
        "packages": {**comparison.packages.as_dict(), "known": comparison.packages_known},
        "services": {**comparison.services.as_dict(), "known": comparison.services_known},
    }
