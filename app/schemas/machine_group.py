"""Pydantic schemas for machine group forms."""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

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
