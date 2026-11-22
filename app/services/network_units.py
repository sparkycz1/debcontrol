"""Network throughput in bytes or bits per second — each account's own
choice (`User.network_units`, set on the Account page or through
`POST /api/v1/account/network-units`). Rates are stored and computed in
bytes per second everywhere; only what is shown changes."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from app.web import charts

BYTES = "bytes"
BITS = "bits"
CHOICES = (BYTES, BITS)


def normalize(value: str | None) -> str:
    return value if value in CHOICES else BYTES


def of(user: Any) -> str:
    """The account's choice; bytes for anyone who never picked (or none)."""
    return normalize(getattr(user, "network_units", None))


def chart_format(units: str) -> str:
    """The chart value format for network rates."""
    return "bits_rate" if units == BITS else "bytes_rate"


def series(values: Iterable[float | None], units: str) -> list[float | None]:
    """A bytes-per-second series in the account's unit."""
    factor = 8 if units == BITS else 1
    return [None if v is None else v * factor for v in values]


def format_rate(bytes_per_second: float | None, units: str) -> str:
    if bytes_per_second is None:
        return "—"
    if units == BITS:
        return charts.format_bits(bytes_per_second * 8)
    return charts.format_bytes(bytes_per_second, "/s")
