"""Free-form tags on a machine (e.g. `prod`, `web`, `praha-dc1`) — a
cross-cutting label independent of `app.db.models.machine_group.
MachineGroup`'s strict one-group-per-machine tree, for filtering that
doesn't need (or fit) a place in that hierarchy. A machine can carry any
number of tags; a tag can be on any number of machines — a plain
many-to-many, via the `machine_tags` association table below.

A `Tag` row is created the first time its name is used and deleted
automatically once no machine references it anymore — see
`app.services.machine_tags.set_machine_tags`, the only place rows in
either table are written. There is no separate "manage tags" page to
keep in sync by hand: renaming is "remove the old one, add the new one"
on each machine, same as any other machine field.

Names are stored lowercased and trimmed (see `app.services.machine_tags.
normalize_tag_names`) — the same "normalize once, on the way in" choice
`User.username` already makes — so `Tag.name` can carry a plain unique
constraint instead of a case-insensitive one.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Column, ForeignKey, String, Table, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

machine_tags = Table(
    "machine_tags",
    Base.metadata,
    Column(
        "machine_id", ForeignKey("machines.id", ondelete="CASCADE"), primary_key=True
    ),
    Column("tag_id", ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True),
)


class Tag(Base):
    __tablename__ = "tags"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"Tag(name={self.name!r})"
