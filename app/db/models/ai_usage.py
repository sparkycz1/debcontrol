"""One provider API call's token usage, for the global AI token limits.

`user_id` is `ON DELETE SET NULL` rather than `CASCADE`: the limits are
**global**, not per-user, so deleting an account must not retroactively
free up budget that was genuinely spent. The column is kept only so an
operator can see who spent what; the accounting itself never needs it.

`created_at` is indexed because that is the only thing the limit queries
filter on — see `app.ai.usage.get_usage_totals`, which sums a rolling time
window (last 24 hours / 7 days / 30 days).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.models.ai_provider import AiProviderKind
from app.db.pg_enum import pg_enum


class AiUsageRecord(Base):
    __tablename__ = "ai_usage_records"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    provider_kind: Mapped[AiProviderKind] = mapped_column(
        pg_enum(AiProviderKind, name="ai_provider_kind"), nullable=False
    )
    model_id: Mapped[str] = mapped_column(String(255), nullable=False)
    input_tokens: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    output_tokens: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), nullable=False, index=True
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return (
            f"AiUsageRecord(provider_kind={self.provider_kind!r}, "
            f"input_tokens={self.input_tokens!r}, output_tokens={self.output_tokens!r})"
        )
