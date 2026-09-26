"""A user's own saved filter on a machine's Logs tab — "journal, errors
only, last hour" or "/var/log/nginx/error.log, search 502" — offered on
every machine's Logs tab, since the point is to replay the same view on
whichever machine you're looking at. Per-account, like
`app.db.models.saved_machine_view.SavedMachineView` (see its docstring for
why), and `query_string` is likewise rebuilt from a fixed set of known
parameters (`app.services.saved_log_views.ALLOWED_LOG_VIEW_PARAMS`), never
stored verbatim from the client.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class SavedLogView(Base):
    __tablename__ = "saved_log_views"
    __table_args__ = (
        UniqueConstraint("user_id", "name", name="uq_saved_log_views_user_id_name"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    query_string: Mapped[str] = mapped_column(String(1000), nullable=False)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
