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
    unexpected_body: str | None = Field(default=None, max_length=200)
    json_path: str | None = Field(default=None, max_length=200)
    json_expected: str | None = Field(default=None, max_length=200)
    max_latency_ms: int | None = Field(default=None, ge=1, le=600000)
    sla_target_percent: float | None = Field(default=None, gt=0, le=100)
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
        self.unexpected_body = (self.unexpected_body or "").strip() or None
        self.json_path = (self.json_path or "").strip() or None
        self.json_expected = (self.json_expected or "").strip() or None
        if self.json_path is None:
            self.json_expected = None
        if self.kind != "http":
            # Body/status assertions only mean something for HTTP — except
            # a DNS check's expected address, kept in `expected_body`.
            self.expected_status = None
            if self.kind != "dns":
                self.expected_body = None
            self.unexpected_body = None
            self.json_path = None
            self.json_expected = None
        return self
