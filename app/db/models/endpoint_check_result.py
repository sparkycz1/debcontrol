"""One stored result of an `EndpointCheck` probe — the history behind a
check's detail page (uptime %, latency chart, recent failures) and
`GET /api/v1/checks/{id}/history`.

Written by `app.tasks.jobs._run_endpoint_check` for every probe, up or
down (an outage is exactly what a history has to capture), alongside the
`last_*` columns on the check itself, which stay the fast "right now"
answer for the list page. Purged together with the machines' monitoring
history, by the same retention setting
(`AppSettings.monitoring_history_retention_days`; see
`app.tasks.jobs._purge_old_monitoring_samples`).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, Float, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class EndpointCheckResult(Base):
    __tablename__ = "endpoint_check_results"
    __table_args__ = (
        # Every read is "one check's results within a time window, oldest
        # first" (detail page, API) and the purge is a time cutoff.
        Index("ix_endpoint_check_results_check_id_checked_at", "check_id", "checked_at"),
        Index("ix_endpoint_check_results_checked_at", "checked_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    check_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("endpoint_checks.id", ondelete="CASCADE"), nullable=False
    )
    checked_at: Mapped[datetime] = mapped_column(nullable=False)
    ok: Mapped[bool] = mapped_column(Boolean, nullable=False)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    error: Mapped[str | None] = mapped_column(String(500), nullable=True)
