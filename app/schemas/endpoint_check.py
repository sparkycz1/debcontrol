"""Validation for creating/editing an `EndpointCheck` — one schema shared by
the web form (`app/web/routes/checks.py`) and the REST API
(`app/web/routes/api_v1_checks.py`)."""

from __future__ import annotations

from pydantic import BaseModel, Field, model_validator

from app.db.models.endpoint_check import CHECK_KINDS
from app.services.endpoint_checks import validate_target


class EndpointCheckSave(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    kind: str
    target: str = Field(min_length=1, max_length=500)
    expected_status: int | None = Field(default=None, ge=100, le=599)
    expected_body: str | None = Field(default=None, max_length=200)
    verify_tls: bool = True
    interval_seconds: int = Field(default=300, ge=30, le=86400)
    timeout_seconds: int = Field(default=10, ge=1, le=60)
    cert_warn_days: int = Field(default=14, ge=0, le=365)
    enabled: bool = True

    @model_validator(mode="after")
    def _check_kind_and_target(self) -> EndpointCheckSave:
        self.name = self.name.strip()
        self.target = self.target.strip()
        if self.kind not in CHECK_KINDS:
            raise ValueError("Unknown check type.")
        error = validate_target(self.kind, self.target)
        if error:
            raise ValueError(error)
        self.expected_body = (self.expected_body or "").strip() or None
        if self.kind == "tls":
            self.expected_status = None
            self.expected_body = None
        return self
