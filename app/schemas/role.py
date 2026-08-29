"""Pydantic schema for the role-management form (`app/web/routes/roles.py`)."""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

from app.db.models.role import Permission


class RoleSave(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    description: str | None = Field(default=None, max_length=500)
    permissions: list[Permission] = Field(default_factory=list)

    @field_validator("name")
    @classmethod
    def _strip_name(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("Name is required.")
        return stripped
