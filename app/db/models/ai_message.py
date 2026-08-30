"""One message in an `AiConversation`, plus any mutating actions the
assistant proposed in it.

Three columns carry three different things, on purpose:

- `content` — the human-readable text rendered in the chat bubble. This is
  the only thing a person ever reads.
- `provider_native` — the raw, provider-shaped message(s) needed to replay
  this turn back to that same provider on the next call. The three wire
  formats this app speaks (Anthropic content blocks, OpenAI `tool_calls` +
  `role: "tool"` messages, Gemini `functionCall`/`functionResponse` parts)
  each require a *different* thing echoed back for a tool round trip to be
  accepted, so this is stored verbatim rather than normalized: a shared
  intermediate format would have to be translated back, lossily, into
  whichever shape the provider actually demands. See `app.ai.base`.
- `pending_actions` — the mutating tool calls the model proposed in this
  turn, each one a self-contained description of what would run and where,
  with a `status` of `pending` / `confirmed` / `discarded` / `denied`.

`pending_actions` is the load-bearing safety structure of the whole
feature. **Nothing in it ever executes on its own.** A mutating tool call
is only ever *recorded* here by the background turn task; execution
requires an explicit, CSRF-protected POST to
`/ai/conversations/{id}/messages/{message_id}/confirm` after a human has
seen the literal command text and target list rendered from this row. The
`denied` status exists so the conversation (and the reader) can see that
the assistant *tried* to propose something the user's role doesn't allow,
rather than the attempt silently vanishing.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, ForeignKey, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.pg_enum import pg_enum


class AiMessageRole(enum.StrEnum):
    USER = "user"
    ASSISTANT = "assistant"


class PendingActionStatus(enum.StrEnum):
    """Status values used inside the `pending_actions` JSON. Deliberately a
    plain Python enum with string values rather than a DB enum — these live
    inside a JSON document, not in a column of their own."""

    PENDING = "pending"
    CONFIRMED = "confirmed"
    DISCARDED = "discarded"
    DENIED = "denied"


class AiMessage(Base):
    __tablename__ = "ai_messages"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    conversation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("ai_conversations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    role: Mapped[AiMessageRole] = mapped_column(
        pg_enum(AiMessageRole, name="ai_message_role"), nullable=False
    )
    content: Mapped[str] = mapped_column(Text, nullable=False, default="")
    provider_native: Mapped[Any | None] = mapped_column(JSON, nullable=True)
    pending_actions: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, nullable=True)

    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"AiMessage(id={self.id!r}, role={self.role!r})"
