"""Request body for acknowledging a problem (shared with the sister app)
(`app.services.acknowledgements`)."""

from __future__ import annotations

from pydantic import BaseModel, Field

from app.services import acknowledgements


class AcknowledgeRequest(BaseModel):
    # None = until the problem is over (or someone clears it).
    hours: int | None = Field(default=None, ge=1, le=acknowledgements.MAX_HOURS)
    note: str | None = Field(default=None, max_length=acknowledgements.MAX_NOTE_LENGTH)
