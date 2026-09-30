"""One model id fetched from a provider's own "list models" endpoint.

Fetching is an explicit admin action ("Fetch models now" on the Settings
page, see `app.ai.providers`), and fetching is deliberately *not* the same
as trusting: every `AiModel` starts `enabled=False` and an admin ticks the
ones that may be picked for a chat conversation. Provider catalogs are
large and contain plenty of models nobody wants a machine-managing
assistant pointed at (tiny/legacy models with no tool-calling, image
models, ...), so an opt-in list is the right default.

A re-fetch upserts: ids that are still present keep their `enabled` flag
(re-fetching must never silently re-disable a model an admin approved, nor
silently enable one they didn't), and ids that disappeared from the
provider are deleted.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class AiModel(Base):
    __tablename__ = "ai_models"
    __table_args__ = (UniqueConstraint("provider_id", "model_id", name="uq_ai_models_provider_id"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    provider_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("ai_provider_configs.id", ondelete="CASCADE"), nullable=False
    )
    # The provider's own id string, exactly as sent back to it later
    # (e.g. "claude-opus-4-20250514", "gpt-4o", "gemini-2.0-flash" — the
    # "models/" prefix Gemini's listing uses is stripped before storing).
    model_id: Mapped[str] = mapped_column(String(255), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    provider: Mapped[AiProviderConfig] = relationship(back_populates="models")

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"AiModel(model_id={self.model_id!r}, enabled={self.enabled!r})"


# Imported last, and only for type checking: every class above is already
# defined by the time this module points back at the models it relates
# to, so no import cycle can leave a class half-defined (CodeQL's
# "Module-level cyclic import"). SQLAlchemy resolves the relationship
# targets by name through its registry, never through these imports.
if TYPE_CHECKING:
    from app.db.models.ai_provider import AiProviderConfig
