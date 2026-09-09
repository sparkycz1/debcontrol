"""Pydantic schemas for exporting/importing role *configuration* — the
same config-as-code convenience `app.schemas.machine_config` already gives
machines/groups, applied to `Role`/`RolePermission`. No credentials or
per-account data involved here (a role has none), so unlike the machine
export this one is a full, lossless round-trip. See
`app.services.role_config` for the conflict-handling policy.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class RoleExport(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    description: str | None = None
    require_totp: bool = False
    # Plain strings, not `list[Permission]` — an export written by a newer
    # debcontrol version may contain a permission this (older) instance
    # doesn't know about yet; keeping this untyped lets import filter those
    # out explicitly (see `import_role_config`) instead of the whole payload
    # failing Pydantic validation before any role can be created at all.
    permissions: list[str] = Field(default_factory=list)


class RoleConfigExport(BaseModel):
    roles: list[RoleExport] = Field(default_factory=list)
