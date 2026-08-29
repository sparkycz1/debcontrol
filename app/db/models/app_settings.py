"""Runtime, user-editable application settings — as opposed to
`app.core.config.Settings`, which comes from the environment and needs a
restart to change. This is a singleton table (one row, fixed id), edited
from the **Settings** page.

Deliberately a separate table/mechanism from `app.core.config.Settings`
rather than, say, letting the Settings page rewrite `.env`: the two have
different lifecycles (env config is infrastructure, decided at deploy
time; this is app behavior, decided by whoever's operating it day to day)
and different trust models (no auth yet — see the Architecture wiki page —
so this is the first *value* editable through the UI, not just secrets
provisioned outside it).
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Integer, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

SINGLETON_ID = 1


class AppSettings(Base):
    __tablename__ = "app_settings"

    id: Mapped[int] = mapped_column(primary_key=True)

    # How many days of audit_log_entries to keep before the daily purge job
    # (app.tasks.jobs.purge_old_audit_log_entries) deletes them. NULL means
    # "keep forever" — the default, since silently discarding audit history
    # is a much worse surprise than an unbounded table.
    audit_log_retention_days: Mapped[int | None] = mapped_column(Integer, nullable=True)

    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), onupdate=func.now(), nullable=False
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"AppSettings(audit_log_retention_days={self.audit_log_retention_days!r})"
