"""Hardware inventory and warranties.

What a physical machine is — vendor, model, serial number — is read from
its firmware with the facts; when it was bought and until when its
warranty runs is typed in by a person. Together they answer "which boxes
run out of warranty this year".

None of it applies to a virtual machine: its "hardware" is its
hypervisor's, and it is shown nowhere for a machine known to be virtual
(`Machine.is_physical` is False). A machine debcontrol could not classify
is treated as possibly physical.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.machine import Machine
from app.db.models.user import User
from app.services.access_scope import machines_visible_to

# Warn this long before a warranty ends.
WARRANTY_SOON_DAYS = 60
_MAX_LISTED = 2000


class AssetError(ValueError):
    """A date that cannot be right — text for the person who typed it."""


def applies(machine: Any) -> bool:
    """Whether hardware and warranty are a thing for this machine."""
    return machine.is_physical is not False


def serial_of(machine: Any) -> str | None:
    """The serial to show: the one typed in wins over the firmware's."""
    serial: str | None = machine.asset_serial or machine.hw_serial
    return serial


def warranty_days_left(machine: Any, today: date | None = None) -> int | None:
    """Days until the warranty ends (negative once it has); None when no
    end is recorded or the machine is virtual."""
    if not applies(machine) or machine.warranty_until is None:
        return None
    return int((machine.warranty_until - (today or datetime.now().date())).days)


def parse_date(value: str, label: str) -> date | None:
    text = value.strip()
    if not text:
        return None
    try:
        parsed = date.fromisoformat(text)
    except ValueError as exc:
        raise AssetError(f"{label}: use a date like 2027-03-31.") from exc
    if not 1990 <= parsed.year <= 2100:
        raise AssetError(f"{label}: the year looks wrong.")
    return parsed


def apply_asset(
    machine: Machine,
    *,
    purchase_date: date | None,
    warranty_until: date | None,
    asset_serial: str,
    asset_note: str,
) -> None:
    """Set what a person records about the machine's hardware."""
    if purchase_date and warranty_until and warranty_until < purchase_date:
        raise AssetError("The warranty cannot end before the purchase.")
    machine.purchase_date = purchase_date
    machine.warranty_until = warranty_until
    machine.asset_serial = " ".join(asset_serial.split())[:128] or None
    machine.asset_note = " ".join(asset_note.split())[:255] or None


@dataclass(frozen=True)
class InventoryRow:
    machine: Machine
    days_left: int | None

    @property
    def state(self) -> str:
        """ "expired" / "soon" / "ok" / "unknown"."""
        if self.days_left is None:
            return "unknown"
        if self.days_left < 0:
            return "expired"
        return "soon" if self.days_left <= WARRANTY_SOON_DAYS else "ok"


def as_dict(machine: Any) -> dict[str, Any] | None:
    """The hardware record for the API; None for a virtual machine."""
    if not applies(machine):
        return None
    return {
        "vendor": machine.hw_vendor,
        "model": machine.hw_model,
        "serial": serial_of(machine),
        "firmware_serial": machine.hw_serial,
        "purchase_date": machine.purchase_date.isoformat() if machine.purchase_date else None,
        "warranty_until": machine.warranty_until.isoformat() if machine.warranty_until else None,
        "warranty_days_left": warranty_days_left(machine),
        "note": machine.asset_note,
    }


async def inventory(db: AsyncSession, user: User) -> list[InventoryRow]:
    """Every machine that is not known to be virtual, among those `user`
    may see — the ones whose warranty ends soonest first, the ones with no
    end recorded last."""
    query = await machines_visible_to(db, user)
    result = await db.execute(
        query.where(Machine.is_physical.is_not(False)).order_by(Machine.name).limit(_MAX_LISTED)
    )
    today = datetime.now().date()
    rows = [InventoryRow(m, warranty_days_left(m, today)) for m in result.scalars().all()]
    rows.sort(key=lambda r: (r.days_left is None, r.days_left or 0, r.machine.name.lower()))
    return rows
