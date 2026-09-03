"""Pydantic schemas for exporting/importing machine & group *configuration*
(Task 1) — deliberately not a credentials backup. See
`app.services.machine_config`'s module docstring for the full design
rationale (what's excluded and why, and the conflict-handling policy).
"""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

from app.db.models.machine import AuthMethod
from app.services.machine_tags import normalize_tag_names


class MachineExport(BaseModel):
    """One machine's structural configuration — no `secret_encrypted`
    (password/key material) and no `host_key_fingerprint`, ever. See
    `app.services.machine_config` for why."""

    name: str = Field(min_length=1, max_length=255)
    ip_address: str = Field(min_length=1, max_length=255)
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(min_length=1, max_length=255)
    auth_method: AuthMethod
    group: str | None = None
    description: str | None = None
    tags: list[str] = Field(default_factory=list)
    is_active: bool = True

    @field_validator("tags")
    @classmethod
    def _normalize_tags(cls, value: list[str]) -> list[str]:
        return normalize_tag_names(value)


class GroupExport(BaseModel):
    """One machine group's configuration. `members` is informational only
    on export (a convenience for a human reading the JSON) — on import,
    membership is always driven by each machine's own `group` field, not by
    this list, so the two can never disagree about who belongs where."""

    name: str = Field(min_length=1, max_length=255)
    description: str | None = None
    members: list[str] = Field(default_factory=list)


class MachineConfigExport(BaseModel):
    """The full export/import payload shape — every non-pending `Machine`
    and every `MachineGroup`."""

    machines: list[MachineExport] = Field(default_factory=list)
    groups: list[GroupExport] = Field(default_factory=list)
