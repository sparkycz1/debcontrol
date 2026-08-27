"""Pydantic schemas for machine forms/API.

`secret` is never returned in responses — the read schema doesn't include
it at all, so a secret can't accidentally leak into JSON/HTML output.
"""

from __future__ import annotations

import ipaddress
import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

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

    @field_validator("ip_address")
    @classmethod
    def _validate_ip_address(cls, value: str) -> str:
        return _check_ip_address(value)


class MachineRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    ip_address: str
    port: int
    username: str
    auth_method: AuthMethod
    host_key_fingerprint: str | None
    group_id: uuid.UUID | None
    description: str | None
    is_active: bool
    discovered_hostname: str | None
    os_version: str | None
    kernel_version: str | None
    cpu_cores: int | None
    ram_bytes: int | None
    disks: list[dict[str, Any]] | None
    facts_updated_at: datetime | None
    is_reachable: bool | None
    last_ping_at: datetime | None
    created_at: datetime
    updated_at: datetime
