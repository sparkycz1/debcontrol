"""A named group of user accounts — exists purely to be targeted by a
`NotificationRule` (see `app.db.models.notification_rule`): "notify
everyone in the on-call group" instead of listing individual users on
every rule. Deliberately independent of `app.db.models.role.Role` (which
answers *what* an account may do, not *who should hear about what*) and of
`app.db.models.machine_group.MachineGroup` (which groups machines, not
users) — a user can belong to any number of these, unlike a machine's
single `MachineGroup`.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Column, ForeignKey, String, Table, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.db.models.user import User

user_group_members = Table(
    "user_group_members",
    Base.metadata,
    Column(
        "user_group_id", ForeignKey("user_groups.id", ondelete="CASCADE"), primary_key=True
    ),
    Column("user_id", ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
)


class UserGroup(Base):
    __tablename__ = "user_groups"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), onupdate=func.now(), nullable=False
    )

    members: Mapped[list[User]] = relationship(secondary=user_group_members, lazy="selectin")

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"UserGroup(id={self.id!r}, name={self.name!r})"
