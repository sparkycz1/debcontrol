"""A picture attached to a user message in an AI conversation.

Kept in its own table rather than inside `AiMessage.provider_native`:

- the history replayed to the provider every turn is built from these rows
  (`app.tasks.ai_jobs._load_history` asks the conversation's client for its
  own wire shape — Anthropic image blocks, OpenAI/OpenRouter `image_url`
  parts, Gemini `inlineData`), so the JSON column stays small and the bytes
  are stored once, not once per provider format;
- the chat shows the picture from here (`GET /ai/conversations/{id}/
  attachments/{attachment_id}`), with the type debcontrol sniffed itself
  (`app.services.ai_attachments`), never the browser's claim.

`data` is deferred: listing a conversation's attachments for the chat page
doesn't load megabytes it never shows inline. Rows go with their message
and conversation (`ON DELETE CASCADE`, plus an explicit delete in
`app.web.routes.ai.delete_conversation` for SQLite in tests).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import ForeignKey, Integer, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class AiAttachment(Base):
    __tablename__ = "ai_attachments"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid7)
    conversation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("ai_conversations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    message_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("ai_messages.id", ondelete="CASCADE"), nullable=False, index=True
    )
    media_type: Mapped[str] = mapped_column(String(32), nullable=False)
    filename: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    size: Mapped[int] = mapped_column(Integer, nullable=False)
    data: Mapped[bytes] = mapped_column(LargeBinary, nullable=False, deferred=True)
    created_at: Mapped[datetime] = mapped_column(default=lambda: datetime.now(UTC), nullable=False)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"AiAttachment(id={self.id!r}, media_type={self.media_type!r})"
