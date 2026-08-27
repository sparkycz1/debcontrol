"""Schema for the self-registration payload posted to POST /api/inform."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class InformPayload(BaseModel):
    """Everything is optional except what the caller can't easily know about
    itself — the request's source IP is used as a fallback for `ip_address`,
    and as `PendingMachine.source_ip` regardless, for cross-checking."""

    hostname: str | None = Field(default=None, max_length=255)
    ip_address: str | None = Field(default=None, max_length=255)
    os_version: str | None = Field(default=None, max_length=255)
    kernel_version: str | None = Field(default=None, max_length=255)
    cpu_cores: int | None = Field(default=None, ge=0)
    ram_bytes: int | None = Field(default=None, ge=0)
    disks: list[dict[str, Any]] | None = None
