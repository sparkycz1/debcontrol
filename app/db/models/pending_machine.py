"""A machine that announced itself via POST /api/inform, awaiting review.

Self-registration is authenticated with a shared bearer token
(`INFORM_TOKEN`), not by anything SSH-related — nothing here is trusted for
connecting to the machine. An operator reviews the entry and, if it looks
right, uses it to pre-fill the normal "add machine" form, which still goes
through the regular host-key discovery/confirmation flow before any SSH
connection is ever attempted.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, BigInteger, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class PendingMachine(Base):
    __tablename__ = "pending_machines"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)

    ip_address: Mapped[str] = mapped_column(String(255), nullable=False)
    reported_hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    os_version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    kernel_version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    cpu_cores: Mapped[int | None] = mapped_column(Integer, nullable=True)
    ram_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    disks: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, nullable=True)

    # The HTTP request's actual source IP, kept for reference/audit — separate
    # from `ip_address`, which is self-reported and may differ (NAT, etc.).
    source_ip: Mapped[str | None] = mapped_column(String(255), nullable=True)

    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"PendingMachine(id={self.id!r}, ip_address={self.ip_address!r})"
