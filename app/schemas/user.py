"""Pydantic schemas for the user-management forms (`app/web/routes/users.py`)."""

from __future__ import annotations

import uuid

from pydantic import BaseModel, Field, field_validator, model_validator

from app.auth.security import USERNAME_PATTERN
from app.db.models.user import AuthProvider

MIN_PASSWORD_LENGTH = 12


class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    display_name: str | None = Field(default=None, max_length=255)
    auth_provider: AuthProvider
    # Required (and validated) only for AuthProvider.LOCAL — see
    # `_check_password_required`. LDAP/OIDC accounts have no debcontrol-side
    # password at all.
    password: str | None = Field(default=None, max_length=255)
    role_id: uuid.UUID

    @field_validator("username")
    @classmethod
    def _normalize_username(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not USERNAME_PATTERN.match(normalized):
            raise ValueError(
                "Username must be 3-64 characters: lowercase letters, digits, '.', '_', or '-', "
                "starting with a letter or digit."
            )
        return normalized

    @field_validator("password")
    @classmethod
    def _validate_password_length(cls, value: str | None) -> str | None:
        if value and len(value) < MIN_PASSWORD_LENGTH:
            raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
        return value

    @model_validator(mode="after")
    def _check_password_required(self) -> UserCreate:
        if self.auth_provider == AuthProvider.LOCAL:
            if not self.password:
                raise ValueError("A local account needs a password.")
        elif self.password:
            raise ValueError(f'"{self.auth_provider.value}" accounts don\'t set a password here.')
        return self


class UserUpdate(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    display_name: str | None = Field(default=None, max_length=255)
    auth_provider: AuthProvider
    # Blank = keep the existing password unchanged (only meaningful when
    # `auth_provider` is already, or is becoming, LOCAL) — same convention as
    # `Machine.secret_encrypted` in app/schemas/machine.py.
    password: str | None = Field(default=None, max_length=255)
    role_id: uuid.UUID
    is_active: bool

    @field_validator("username")
    @classmethod
    def _normalize_username(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not USERNAME_PATTERN.match(normalized):
            raise ValueError(
                "Username must be 3-64 characters: lowercase letters, digits, '.', '_', or '-', "
                "starting with a letter or digit."
            )
        return normalized

    @field_validator("password")
    @classmethod
    def _validate_password_length(cls, value: str | None) -> str | None:
        if value and len(value) < MIN_PASSWORD_LENGTH:
            raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
        return value
