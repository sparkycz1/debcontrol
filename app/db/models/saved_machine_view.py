"""A user's own saved filter on the machine list — "Save this view" next
to the search form on **Machines**, so a combination like `tag=prod` (or
`q=web&tag=praha-dc1`) doesn't need retyping every visit.

Deliberately per-account, not shared/global: a view is a personal
shortcut, the same way a browser bookmark is, not fleet configuration —
there's nothing here that needs an admin permission beyond ordinary
`machine.view` (already required to reach the machine list at all).

`query_string` is a plain, already-URL-encoded query string built from a
small fixed set of known parameters (`q`, `tag` — see `app.web.routes.
machines`'s `_ALLOWED_SAVED_VIEW_PARAMS`), never accepted verbatim from
the client: a saved view is meant to replay a *filter*, not an arbitrary
querystring, and validating the parameter names keeps a stale/renamed
filter parameter from silently saving as a dead link.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class SavedMachineView(Base):
    __tablename__ = "saved_machine_views"
    __table_args__ = (
        # A user can't save two views with the same name — keeps the list
        # unambiguous without needing its own rename/dedupe UI.
        UniqueConstraint("user_id", "name", name="uq_saved_machine_views_user_id_name"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    query_string: Mapped[str] = mapped_column(String(500), nullable=False)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"SavedMachineView(name={self.name!r}, query_string={self.query_string!r})"
