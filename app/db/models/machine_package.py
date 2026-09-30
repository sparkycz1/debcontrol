"""One installed package on a managed machine, as of the last package
refresh — see `app.ssh.packages` for how it's gathered and
`app.tasks.jobs.refresh_machine_packages` for how it's kept in sync.

Each refresh replaces a machine's whole set of rows in one transaction
(delete-then-bulk-insert) rather than diffing — it's a snapshot of "what's
installed right now," not a history of package changes.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, ForeignKey, Index, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.pg_enum import pg_enum
from app.ssh.packages import PackageSource


class MachinePackage(Base):
    __tablename__ = "machine_packages"
    __table_args__ = (
        Index("ix_machine_packages_machine_id_source", "machine_id", "source"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)

    machine_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("machines.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # One-directional — Machine deliberately has no `packages` relationship
    # back (a machine's package list can run into the thousands, and every
    # place that needs it already queries MachinePackage directly rather
    # than eager-loading through Machine). Used by the fleet-wide package
    # search, which needs each hit's machine name/id.
    machine: Mapped[Machine] = relationship(viewonly=True)

    source: Mapped[PackageSource] = mapped_column(
        pg_enum(PackageSource, name="package_source"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str] = mapped_column(String(255), nullable=False)
    # apt-only ("apt-mark showhold") — always False for flatpak/snap, which
    # have no equivalent concept.
    held: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return (
            f"MachinePackage(machine_id={self.machine_id!r}, source={self.source!r}, "
            f"name={self.name!r})"
        )


# Imported last, and only for type checking: every class above is already
# defined by the time this module points back at the models it relates
# to, so no import cycle can leave a class half-defined (CodeQL's
# "Module-level cyclic import"). SQLAlchemy resolves the relationship
# targets by name through its registry, never through these imports.
if TYPE_CHECKING:
    from app.db.models.machine import Machine
