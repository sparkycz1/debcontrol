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

from sqlalchemy import Enum, ForeignKey, Index, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
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

    source: Mapped[PackageSource] = mapped_column(
        Enum(PackageSource, name="package_source", native_enum=True), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str] = mapped_column(String(255), nullable=False)

    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return (
            f"MachinePackage(machine_id={self.machine_id!r}, source={self.source!r}, "
            f"name={self.name!r})"
        )
