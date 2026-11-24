"""A machine's **usual behavior**: for each hour of the week, what its CPU,
memory, load, network traffic and internet latency normally are — learned
from its own monitoring history (`app.services.machine_baseline`) and
recomputed every night (`app.tasks.baselines`).

One row per machine, the numbers in one JSON document, so the table stays
as small as the fleet and the machine row itself (read everywhere) does not
carry it.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, ForeignKey, Integer
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class MachineBaseline(Base):
    __tablename__ = "machine_baselines"

    machine_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("machines.id", ondelete="CASCADE"), primary_key=True
    )
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # The oldest sample that went into it: the baseline counts only once it
    # covers enough weeks (`machine_baseline.MIN_HISTORY`).
    since: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    sample_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    # {"metrics": {"cpu": [null | [n, median, spread, p95], ...168]}, ...}
    # — see `machine_baseline.Baseline`.
    data: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
