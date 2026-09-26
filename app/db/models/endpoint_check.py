"""One TLS certificate or HTTP endpoint check, run from the debcontrol
server itself (not from a managed machine) — see
`app.services.endpoint_checks` for the probes and the notification
transitions, `app.tasks.jobs.run_due_endpoint_checks` for scheduling.

The `last_*` columns are the latest result — "is it up right now, and
when does its certificate expire" for the list page. Every probe is also
kept as an `EndpointCheckResult` row (uptime/latency history).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, Float, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

CHECK_KINDS = ("http", "tls")


class EndpointCheck(Base):
    __tablename__ = "endpoint_checks"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    # "http" — a GET against `target` (a full http(s):// URL); an https URL
    # also reports its certificate's expiry. "tls" — a TLS handshake with
    # `target` as `host:port` (443 when no port), certificate expiry only.
    kind: Mapped[str] = mapped_column(String(8), nullable=False)
    target: Mapped[str] = mapped_column(String(500), nullable=False)
    # HTTP only: the exact status code that counts as up; None = any < 400.
    expected_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # HTTP only: text that must appear in the response body (case-sensitive,
    # searched in the first `app.services.endpoint_checks.MAX_BODY_BYTES`);
    # None = the status code alone decides. Catches "200 OK, but it's the
    # maintenance page".
    expected_body: Mapped[str | None] = mapped_column(String(200), nullable=True)
    # HTTP only: text that must NOT appear in the body (same search window)
    # — "Internal Server Error", "maintenance", a stack-trace marker.
    unexpected_body: Mapped[str | None] = mapped_column(String(200), nullable=True)
    # HTTP only: a JSON assertion on the response — `json_path` is a dotted
    # path into the parsed body (`status`, `checks.db.ok`, `items.0.state`),
    # `json_expected` the value it must equal, compared as JSON text
    # (`true`, `42`, `ok`); no expected value = the path just has to exist
    # and not be null/false. See `app.services.endpoint_checks.evaluate_json_path`.
    json_path: Mapped[str | None] = mapped_column(String(200), nullable=True)
    json_expected: Mapped[str | None] = mapped_column(String(200), nullable=True)
    # Slower than this counts as a failure ("up, but unusably slow");
    # None = no latency limit. HTTP and TLS alike.
    max_latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # The availability this check promises, e.g. 99.9 — only used by the
    # monthly SLA report (`app.services.endpoint_sla`); None = no target.
    sla_target_percent: Mapped[float | None] = mapped_column(Float, nullable=True)
    verify_tls: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    interval_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=300)
    timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=10)
    # Warn this many days before the certificate expires.
    cert_warn_days: Mapped[int] = mapped_column(Integer, nullable=False, default=14)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # --- Latest result ---
    last_checked_at: Mapped[datetime | None] = mapped_column(nullable=True)
    last_ok: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    last_status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    cert_expires_at: Mapped[datetime | None] = mapped_column(nullable=True)
    # --- Notification state ---
    consecutive_failures: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Whether a "down" notification went out for the current outage, so
    # recovery is announced only after an announced outage.
    down_notified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # The `cert_expires_at` value an "expiring" notification was already
    # sent for — one warning per certificate, a renewed one warns again.
    cert_warned_for: Mapped[datetime | None] = mapped_column(nullable=True)

    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"EndpointCheck(name={self.name!r}, kind={self.kind!r}, target={self.target!r})"
