"""Pydantic schémata pro formuláře/API kolem strojů.

`secret` se do odpovědí nikdy nevrací — schémata pro čtení ho neobsahují
vůbec, aby nešlo tajemství omylem vyzradit v JSON/HTML výstupu.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.db.models.machine import AuthMethod


class MachineCreate(BaseModel):
    hostname: str = Field(min_length=1, max_length=255)
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(min_length=1, max_length=255)
    auth_method: AuthMethod
    secret: str | None = Field(default=None, description="Heslo nebo obsah privátního klíče.")
    description: str | None = Field(default=None, max_length=1024)


class MachineUpdate(BaseModel):
    hostname: str | None = Field(default=None, min_length=1, max_length=255)
    port: int | None = Field(default=None, ge=1, le=65535)
    username: str | None = Field(default=None, min_length=1, max_length=255)
    auth_method: AuthMethod | None = None
    secret: str | None = None
    description: str | None = Field(default=None, max_length=1024)
    is_active: bool | None = None


class MachineRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    hostname: str
    port: int
    username: str
    auth_method: AuthMethod
    host_key_fingerprint: str | None
    description: str | None
    is_active: bool
    created_at: datetime
    updated_at: datetime
