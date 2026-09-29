"""One AI assistant chat thread, owned by exactly one user.

A conversation is **private to the user who created it** — there is no
shared or admin-visible view, deliberately (see `wiki/AI-Assistant`'s
"Deliberately out of scope"). Every route in `app.web.routes.ai` filters on
`user_id` rather than only on the conversation id, so another account
(including an admin) gets a 404, not someone else's thread. What actually
*ran* on a machine as a result of a conversation is still fully visible to
anyone with `audit.view`, in the audit log, like every other mutating
action in this app — the privacy here is over the chat text, not over the
consequences.

`provider_id` + `model_id` are fixed at creation time and never change for
the life of the conversation, matching how a `ScheduledTask`'s target is
fixed: the stored per-message `provider_native` history is shaped for one
specific provider's wire format (see `app.db.models.ai_message`), so
switching providers mid-thread would mean replaying a history the new
provider can't parse.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.models.ai_provider import AiProviderConfig

# The title is derived from the first user message rather than asked of the
# model — a second provider call (with its own cost, latency, and failure
# mode) to produce a list label would be a poor trade.
TITLE_MAX_CHARS = 60


def derive_title(first_message: str) -> str:
    """First ~60 characters of the first user message, on one line."""
    collapsed = " ".join(first_message.split())
    if not collapsed:
        return "New conversation"
    if len(collapsed) <= TITLE_MAX_CHARS:
        return collapsed
    return collapsed[: TITLE_MAX_CHARS - 1].rstrip() + "…"


class AiConversation(Base):
    __tablename__ = "ai_conversations"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)

    provider_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("ai_provider_configs.id", ondelete="CASCADE"), nullable=False
    )
    provider: Mapped[AiProviderConfig] = relationship(lazy="selectin")
    model_id: Mapped[str] = mapped_column(String(255), nullable=False)

    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), onupdate=func.now(), nullable=False
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"AiConversation(id={self.id!r}, title={self.title!r})"
