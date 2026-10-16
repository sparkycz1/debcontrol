"""One Lynis security audit of one machine (`lynis audit system`, see
`app.ssh.lynis` for the command and the report parsing and
`app.services.security_audit` for starting runs and reading results).

The parsed findings are kept on the row itself (`warnings`/`suggestions`,
debcontrol's own `checks`, Lynis's per-setting `details` and a few `facts`)
rather than in tables of their own: they are only ever read together, per
audit, and a machine keeps just its last few audits
(`app.services.security_audit.KEEP_PER_MACHINE`).

`SecurityAuditSuppression` is a finding someone marked as fine on one
machine ("OK"): it stays listed, apart, and no longer counts. It outlives
the audits, matched by the finding's key
(`app.services.security_audit.finding_key`).
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, ForeignKey, Index, Integer, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.models.machine import Machine
from app.db.pg_enum import pg_enum


class SecurityAuditStatus(enum.StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class SecurityAudit(Base):
    __tablename__ = "security_audits"
    __table_args__ = (Index("ix_security_audits_machine_created", "machine_id", "created_at"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    machine_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("machines.id", ondelete="CASCADE"), nullable=False
    )
    machine: Mapped[Machine] = relationship()
    status: Mapped[SecurityAuditStatus] = mapped_column(
        pg_enum(SecurityAuditStatus, name="security_audit_status"),
        nullable=False,
        default=SecurityAuditStatus.PENDING,
    )
    # Install Lynis with apt-get first when the machine has none.
    install_if_missing: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    started_by: Mapped[str | None] = mapped_column(String(255), nullable=True)

    lynis_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # False: Lynis ran without root (no sudo grant for it), so tests that
    # need root were skipped and the index is not comparable to a full run.
    privileged: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    hardening_index: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tests_done: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # [{"test": "SSH-7408", "text": "...", "detail": "...", "solution": "..."}]
    warnings: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, nullable=True)
    suggestions: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, nullable=True)
    # debcontrol's own checks (`app.ssh.security_checks`):
    # [{"id": "firewall", "status": "fail", "value": "..."}]
    checks: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, nullable=True)
    # Lynis `details[]`: [{"test", "service", "desc", "field", "prefval", "value"}]
    details: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, nullable=True)
    # A few Lynis report facts (`app.ssh.lynis._FACTS`).
    facts: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    error: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    started_at: Mapped[datetime | None] = mapped_column(nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(nullable=True)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"SecurityAudit(id={self.id!r}, status={self.status!r})"


class SecurityAuditSuppression(Base):
    """One finding marked "OK" on one machine."""

    __tablename__ = "security_audit_suppressions"
    __table_args__ = (
        UniqueConstraint("machine_id", "key", name="uq_security_audit_suppressions_machine_key"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    machine_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("machines.id", ondelete="CASCADE"), nullable=False
    )
    # `lynis:<TEST-ID>:<hash>` or `check:<id>`.
    key: Mapped[str] = mapped_column(String(128), nullable=False)
    # The finding's text when it was marked, to list it while no audit
    # reports it.
    label: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    note: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
