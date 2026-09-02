"""Pydantic schemas for machine forms.

`secret` is only ever an input here — nothing in this module represents an
outbound/read shape, so there's no risk of it accidentally round-tripping
into a response.
"""

from __future__ import annotations

import ipaddress
import uuid

from pydantic import BaseModel, Field, field_validator

from app.db.models.machine import AuthMethod


def _check_ip_address(value: str) -> str:
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError(f'"{value}" is not a valid IP address.') from exc
    return value


class MachineCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    ip_address: str = Field(min_length=1, max_length=255)
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(min_length=1, max_length=255)
    auth_method: AuthMethod
    secret: str | None = Field(
        default=None, description="Password — only used when auth_method is 'password'."
    )
    group_id: uuid.UUID | None = None
    description: str | None = Field(default=None, max_length=1024)

    @field_validator("ip_address")
    @classmethod
    def _validate_ip_address(cls, value: str) -> str:
        return _check_ip_address(value)


class MachineUpdate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    ip_address: str = Field(min_length=1, max_length=255)
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(min_length=1, max_length=255)
    auth_method: AuthMethod
    secret: str | None = Field(
        default=None,
        description="Password — leave empty to keep the current one unchanged.",
    )
    group_id: uuid.UUID | None = None
    description: str | None = Field(default=None, max_length=1024)
    is_active: bool = True
    # Per-machine overrides of the global `.env` sweep cadences — `None`
    # means "use the global default" (see `Machine.
    # reachability_check_interval_seconds`/`facts_refresh_interval_seconds`).
    reachability_check_interval_seconds: int | None = Field(default=None, ge=1)
    facts_refresh_interval_seconds: int | None = Field(default=None, ge=1)
    monitoring_interval_seconds: int | None = Field(default=None, ge=1)
    monitoring_history_retention_days: int | None = Field(default=None, ge=1)

    @field_validator("ip_address")
    @classmethod
    def _validate_ip_address(cls, value: str) -> str:
        return _check_ip_address(value)
