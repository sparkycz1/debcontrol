"""Pydantic schemas for machine group forms."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

# "All machines" is a built-in, automatic virtual group (see
# app/web/routes/machine_groups.py) — reserved so a real, manually-managed
# group can't be created with the same name and confuse the two.
RESERVED_GROUP_NAMES = {"all"}


class MachineGroupCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=1024)

    @field_validator("name")
    @classmethod
    def _reject_reserved_name(cls, value: str) -> str:
        if value.strip().lower() in RESERVED_GROUP_NAMES:
            raise ValueError(
                f'"{value}" is a reserved name (the built-in "All machines" group) '
                "— pick a different name."
            )
        return value


class MachineGroupRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    description: str | None
    created_at: datetime
    updated_at: datetime
