"""Pydantic schemas for the user-management forms (`app/web/routes/users.py`)."""

from __future__ import annotations

import uuid

from pydantic import BaseModel, Field, field_validator, model_validator

from app.auth.security import USERNAME_PATTERN
from app.db.models.user import AuthProvider

MIN_PASSWORD_LENGTH = 12

# Deliberately not `pydantic.EmailStr` — that needs the optional
# `email-validator` package, which isn't a dependency here. A loose "has an
# `@` with something on each side" check is enough: this address is only
# ever used to send a notification (`app.services.notifications`), never to
# prove identity or gate access the way `username` does, so rejecting a
# technically-valid-but-unusual address is a worse failure mode than
# accepting one that later just bounces. Plain string checks, not a regex:
# `local@domain.tld`, no whitespace, exactly one `@` (and no backtracking
# to worry about on a hostile input).
_EMAIL_MAX_LENGTH = 254


def _looks_like_email(value: str) -> bool:
    if len(value) > _EMAIL_MAX_LENGTH or any(ch.isspace() for ch in value):
        return False
    local, at, domain = value.partition("@")
    if not at or not local or "@" in domain:
        return False
    name, dot, tld = domain.rpartition(".")
    return bool(dot and name and tld)


def normalize_email(value: str | None) -> str | None:
    """Shared by `UserCreate`/`UserUpdate` — blank means "no email set",
    same as every other optional text field here; anything else must look
    like an address. Lowercased for the same reason `username` is: it's
    matched/compared elsewhere (notification recipient de-duplication)
    without needing a case-insensitive comparison everywhere that happens."""
    if not value or not value.strip():
        return None
    normalized = value.strip().lower()
    if not _looks_like_email(normalized):
        raise ValueError("Email must look like name@example.com.")
    return normalized


class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    display_name: str | None = Field(default=None, max_length=255)
    email: str | None = Field(default=None, max_length=255)
    auth_provider: AuthProvider
    # Required (and validated) only for AuthProvider.LOCAL — see
    # `_check_password_required`. LDAP/OIDC accounts have no debcontrol-side
    # password at all.
    password: str | None = Field(default=None, max_length=255)
    role_id: uuid.UUID
    api_access_enabled: bool = False

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

    @field_validator("email")
    @classmethod
    def _validate_email(cls, value: str | None) -> str | None:
        return normalize_email(value)

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
    email: str | None = Field(default=None, max_length=255)
    auth_provider: AuthProvider
    # Blank = keep the existing password unchanged (only meaningful when
    # `auth_provider` is already, or is becoming, LOCAL) — same convention as
    # `Machine.secret_encrypted` in app/schemas/machine.py.
    password: str | None = Field(default=None, max_length=255)
    role_id: uuid.UUID
    is_active: bool
    api_access_enabled: bool = False

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

    @field_validator("email")
    @classmethod
    def _validate_email(cls, value: str | None) -> str | None:
        return normalize_email(value)
