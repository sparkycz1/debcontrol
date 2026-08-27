"""Model for grouping managed machines (e.g. by environment, role, or site)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.db.models.machine import Machine


class MachineGroup(Base):
    """A named group of machines, e.g. "production", "web-servers", "office-lan"."""

    __tablename__ = "machine_groups"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), onupdate=func.now(), nullable=False
    )

    machines: Mapped[list[Machine]] = relationship(back_populates="group")

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"MachineGroup(id={self.id!r}, name={self.name!r})"
