"""A user's own saved filter on the Audit log — "Save this view" next to
the search form on **Audit**, the same convenience `SavedMachineView`
already gives the Machines list (see that model's own docstring for the
general reasoning, which applies here unchanged: per-account, not shared;
`query_string` is a plain, already-URL-encoded string built only from a
small fixed set of known parameters, never accepted verbatim from the
client — see `app.services.saved_audit_views.ALLOWED_VIEW_PARAMS`).

A separate table rather than a shared/generic one: each domain's saved
views capture a different, fixed set of filter parameters, and keeping
them apart means neither one's allowed-parameter list has to account for
the other's.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class SavedAuditView(Base):
    __tablename__ = "saved_audit_views"
    __table_args__ = (
        UniqueConstraint("user_id", "name", name="uq_saved_audit_views_user_id_name"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    query_string: Mapped[str] = mapped_column(String(500), nullable=False)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"SavedAuditView(name={self.name!r}, query_string={self.query_string!r})"
