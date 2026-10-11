"""Each account's own Dashboard: which sections it shows and in what order
(`User.dashboard_layout`). Shared by the Dashboard page
(`app/web/routes/dashboard.py`) and the REST API
(`app/web/routes/api_v1_account.py`).

A stored layout is `{"order": [...], "hidden": [...]}` of section keys.
It is read through `resolve`, never directly: a key this version does not
know is dropped and a section added in a later version is appended, so a
layout saved long ago keeps working after an upgrade.

Hiding a section is a matter of taste, not of access: a section the
account may not see stays absent whatever its layout says.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# In the order they appear when an account has not arranged anything.
SECTIONS = ("machines", "summary", "trends", "scheduling", "activity", "fleet")


class UnknownSectionError(ValueError):
    """Not one of `SECTIONS`."""


@dataclass(frozen=True)
class Layout:
    order: tuple[str, ...]
    hidden: frozenset[str]

    @property
    def visible(self) -> tuple[str, ...]:
        return tuple(key for key in self.order if key not in self.hidden)

    @property
    def is_default(self) -> bool:
        return self.order == SECTIONS and not self.hidden

    def as_dict(self) -> dict[str, list[str]]:
        return {"order": list(self.order), "hidden": [k for k in self.order if k in self.hidden]}


DEFAULT = Layout(order=SECTIONS, hidden=frozenset())


def resolve(stored: Any) -> Layout:
    """The layout to use for whatever is stored: known sections in the
    stored order, then any section the stored layout does not mention."""
    if not isinstance(stored, dict):
        return DEFAULT
    raw_order = stored.get("order")
    raw_hidden = stored.get("hidden")
    order: list[str] = []
    for key in raw_order if isinstance(raw_order, list) else []:
        if key in SECTIONS and key not in order:
            order.append(key)
    order.extend(key for key in SECTIONS if key not in order)
    hidden = frozenset(
        key for key in (raw_hidden if isinstance(raw_hidden, list) else []) if key in SECTIONS
    )
    return Layout(order=tuple(order), hidden=hidden)


def _require(key: str) -> None:
    if key not in SECTIONS:
        raise UnknownSectionError(key)


def move(layout: Layout, key: str, *, up: bool) -> Layout:
    """`key` one place earlier (or later); unchanged at either end."""
    _require(key)
    order = list(layout.order)
    index = order.index(key)
    target = index - 1 if up else index + 1
    if 0 <= target < len(order):
        order[index], order[target] = order[target], order[index]
    return Layout(order=tuple(order), hidden=layout.hidden)


def set_hidden(layout: Layout, key: str, *, hidden: bool) -> Layout:
    _require(key)
    return Layout(
        order=layout.order, hidden=layout.hidden | {key} if hidden else layout.hidden - {key}
    )


def to_store(layout: Layout) -> dict[str, list[str]] | None:
    """What goes into `User.dashboard_layout`: None for the default, so an
    account that never arranged anything follows future defaults."""
    return None if layout.is_default else layout.as_dict()
