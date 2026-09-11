"""Runtime, user-editable application settings — as opposed to
`app.core.config.Settings`, which comes from the environment and needs a
restart to change. This is a singleton table (one row, fixed id), edited
from the **Settings** page.

Deliberately a separate table/mechanism from `app.core.config.Settings`
rather than, say, letting the Settings page rewrite `.env`: the two have
different lifecycles (env config is infrastructure, decided at deploy
time; this is app behavior, decided by whoever's operating it day to day)
and different trust models — this was the first *value* editable through
the UI, not just secrets provisioned outside it.

Also holds the LDAP and OIDC configuration used for user login (see
`app.auth.ldap` / `app.auth.oidc`) and the syslog forwarding configuration
(see `app.audit_syslog`) — deliberately settings-page config, not
environment variables, same reasoning as retention: these are things
whoever's operating the app day to day turns on/off and tunes, not
deploy-time infrastructure. Secrets in here (`ldap_bind_password_encrypted`,
`oidc_client_secret_encrypted`) are encrypted at rest with
`app.core.security` (the same Fernet key as SSH passwords), exactly like
`Machine.secret_encrypted`.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, Integer, LargeBinary, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.pg_enum import pg_enum

SINGLETON_ID = 1

# Sensible default for a typical OpenLDAP directory — Active Directory
# deployments commonly need "(sAMAccountName={username})" instead. `{username}`
# is filter-escaped before substitution (see app.auth.ldap).
DEFAULT_LDAP_USER_SEARCH_FILTER = "(uid={username})"
DEFAULT_OIDC_USERNAME_CLAIM = "email"
DEFAULT_OIDC_SCOPES = "openid email profile"


class SyslogProtocol(enum.StrEnum):
    """Transport for `app.audit_syslog` — UDP and TCP are plaintext (RFC 6587
    octet-counting framing for TCP; UDP needs none, one datagram per
    message); TLS wraps the same TCP framing in a TLS session, for sending
    to a SIEM over an untrusted network."""

    UDP = "udp"
    TCP = "tcp"
    TLS = "tls"


DEFAULT_SYSLOG_PORT = 514


class SmtpEncryption(enum.StrEnum):
    """Transport security for the SMTP relay (config only, for now — see
    `AppSettings.smtp_*`'s own comment for what's built and what's a
    deliberate follow-up). `NONE` is plaintext, for an internal/trusted
    relay only; `STARTTLS` upgrades a plain connection (the common case,
    port 587); `SSL_TLS` connects already-encrypted from the start (the
    older convention, typically port 465)."""

    NONE = "none"
    STARTTLS = "starttls"
    SSL_TLS = "ssl_tls"


DEFAULT_SMTP_PORT = 587


class FleetSummaryFrequency(enum.StrEnum):
    """How often `app.tasks.ai_jobs.generate_fleet_summary` writes a new
    `FleetSummary` row — see that module and `AppSettings.
    fleet_summary_frequency`. `DISABLED` (the default) means the daily Beat
    tick checking this setting is a no-op — no AI provider is ever called
    unless an admin opts in."""

    DISABLED = "disabled"
    DAILY = "daily"
    WEEKLY = "weekly"


class AppSettings(Base):
    __tablename__ = "app_settings"

    id: Mapped[int] = mapped_column(primary_key=True)

    # How many days of audit_log_entries to keep before the daily purge job
    # (app.tasks.jobs.purge_old_audit_log_entries) deletes them. NULL means
    # "keep forever" — the default, since silently discarding audit history
    # is a much worse surprise than an unbounded table.
    audit_log_retention_days: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Same idea, for the daily fleet_snapshots row written by
    # app.tasks.jobs.record_fleet_snapshot and purged by
    # app.tasks.jobs.purge_old_fleet_snapshots. Unlike the audit log, this
    # defaults to a bounded window (90 days) rather than "keep forever" —
    # it's a lightweight, purely-derived trend for the Dashboard chart, not
    # a compliance/audit record, so there's no reason to accumulate it
    # unboundedly by default. NULL still means "keep forever" if an operator
    # wants that.
    dashboard_trends_retention_days: Mapped[int | None] = mapped_column(
        Integer, nullable=True, default=90
    )

    # Same idea again, for `MachineUpdateRun` rows (app.tasks.jobs.
    # purge_old_machine_update_runs) — each one can hold up to ~200KB of apt
    # output (see _MAX_STORED_OUTPUT_CHARS in app.tasks.jobs), and a fleet
    # running recurring scheduled updates (see Scheduling) on hundreds/
    # thousands of machines accumulates these forever with nothing else to
    # bound the table. The actual audit-worthy fact — *that* an update was
    # triggered, by whom — is the separate `machine.updates.run` audit log
    # entry recorded at trigger time and unaffected by this; what gets
    # purged here is only the stored run record and its raw output.
    # Defaults to a bounded window (90 days) for the same reason
    # dashboard_trends_retention_days does: this is operational/diagnostic
    # data, not a compliance record, so there's no reason to accumulate it
    # unboundedly by default. NULL still means "keep forever."
    machine_update_run_retention_days: Mapped[int | None] = mapped_column(
        Integer, nullable=True, default=90
    )

    # Same idea again, for `MachineMonitoringSample` rows (app.tasks.jobs.
    # purge_old_monitoring_samples) — a row is taken every
    # `MONITORING_INTERVAL_SECONDS` (2 minutes by default) for every
    # machine, so this is the one retention setting most likely to matter
    # for table size at fleet scale (see wiki/Host-Requirements.md).
    # Defaults to a bounded window (90 days) for the same "operational
    # trend data, not a compliance record" reasoning as the two above. NULL
    # still means "keep forever." Overridable per machine — see
    # `Machine.monitoring_history_retention_days`.
    monitoring_history_retention_days: Mapped[int | None] = mapped_column(
        Integer, nullable=True, default=90
    )

    # --- AI assistant token limits (app.ai.usage) ---
    #
    # Global (fleet-wide, not per-user) ceilings on total tokens — input +
    # output, summed across every provider and model — spent by the AI
    # assistant in a rolling window. Same shape and spirit as the two
    # retention settings above: NULL means "no limit", which is the default.
    #
    # "Day"/"week"/"month" here are rolling windows (the last 24 hours, 7
    # days, 30 days), NOT calendar-aligned buckets — see
    # `app.ai.usage.check_within_limits` and the wiki page for why that's the
    # deliberate choice.
    ai_daily_token_limit: Mapped[int | None] = mapped_column(Integer, nullable=True)
    ai_weekly_token_limit: Mapped[int | None] = mapped_column(Integer, nullable=True)
    ai_monthly_token_limit: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # --- Scheduled fleet summary (app.tasks.ai_jobs.generate_fleet_summary) ---
    # Off by default — unlike the always-on daily FleetSnapshot row, this is
    # a genuine AI API call with a genuine token cost, so an admin opts in
    # explicitly and picks which configured model pays for it.
    fleet_summary_frequency: Mapped[FleetSummaryFrequency] = mapped_column(
        pg_enum(FleetSummaryFrequency, name="fleet_summary_frequency"),
        default=FleetSummaryFrequency.DISABLED,
        nullable=False,
    )
    fleet_summary_provider_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("ai_provider_configs.id", ondelete="SET NULL"), nullable=True
    )
    fleet_summary_model_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Same "operational/derived data, not a compliance record" reasoning as
    # dashboard_trends_retention_days — bounded by default (roughly six
    # months of history to browse "what's changed"), NULL means keep forever.
    fleet_summary_retention_days: Mapped[int | None] = mapped_column(
        Integer, nullable=True, default=180
    )

    # --- LDAP login (app.auth.ldap) ---
    ldap_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    ldap_server_uri: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ldap_use_starttls: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # Service/bind account used to search for the user's DN — the user's own
    # credentials are only ever used for the final bind-as-them check (see
    # app.auth.ldap.authenticate).
    ldap_bind_dn: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ldap_bind_password_encrypted: Mapped[bytes | None] = mapped_column(
        LargeBinary, nullable=True
    )
    ldap_user_search_base: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ldap_user_search_filter: Mapped[str] = mapped_column(
        String(255), default=DEFAULT_LDAP_USER_SEARCH_FILTER, nullable=False
    )
    ldap_connect_timeout_seconds: Mapped[int] = mapped_column(Integer, default=5, nullable=False)
    # Verify the directory's TLS certificate against the system CA bundle
    # for `ldaps://`/STARTTLS — on by default. Turning it off accepts any
    # certificate (self-signed, expired, wrong hostname) with no chain-of-
    # trust check at all, an explicit opt-out for a directory whose
    # certificate an admin already knows isn't (or can't easily be made)
    # verifiable, not a default anyone should want. See app.auth.ldap.
    ldap_tls_verify: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # --- OIDC login (app.auth.oidc) ---
    oidc_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    oidc_issuer_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    oidc_client_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    oidc_client_secret_encrypted: Mapped[bytes | None] = mapped_column(
        LargeBinary, nullable=True
    )
    # Which ID-token claim is compared against a user's `username` to decide
    # which debcontrol account just logged in — see the module docstring and
    # User.username. Configurable since it varies by provider.
    oidc_username_claim: Mapped[str] = mapped_column(
        String(100), default=DEFAULT_OIDC_USERNAME_CLAIM, nullable=False
    )
    oidc_scopes: Mapped[str] = mapped_column(
        String(255), default=DEFAULT_OIDC_SCOPES, nullable=False
    )
    # Shown on the login button ("Log in with {name}") instead of the
    # generic "OIDC" — purely cosmetic, e.g. "Entra ID"/"Authentik"/"Google
    # Workspace". Blank (the default) falls back to the generic label; see
    # login.html.
    oidc_provider_name: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # --- Syslog forwarding of audit log entries (app.audit_syslog), e.g. to
    # a SIEM. Best-effort/fire-and-forget: the DB row is always the source
    # of truth, this is only ever a live mirror of it. ---
    syslog_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    syslog_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    syslog_port: Mapped[int] = mapped_column(Integer, default=DEFAULT_SYSLOG_PORT, nullable=False)
    syslog_protocol: Mapped[SyslogProtocol] = mapped_column(
        pg_enum(SyslogProtocol, name="syslog_protocol"),
        default=SyslogProtocol.UDP,
        nullable=False,
    )

    # --- SMTP relay — configuration only, for now. Nothing in the app
    # sends an email through this yet; this round is just the Settings →
    # Integrations section so the relay can be set up and saved ahead of an
    # actual notification feature (e.g. on a failed update run or an
    # offline machine), a deliberate follow-up. Same encrypted-secret
    # convention as `ldap_bind_password_encrypted`/`oidc_client_secret_encrypted`
    # above. ---
    smtp_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    smtp_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    smtp_port: Mapped[int] = mapped_column(Integer, default=DEFAULT_SMTP_PORT, nullable=False)
    smtp_encryption: Mapped[SmtpEncryption] = mapped_column(
        pg_enum(SmtpEncryption, name="smtp_encryption"),
        default=SmtpEncryption.STARTTLS,
        nullable=False,
    )
    smtp_username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    smtp_password_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    # Envelope/header From — most relays (and SPF/DKIM-checking recipients)
    # reject a send whose From doesn't match an address the relay account is
    # actually allowed to send as, so this is its own field rather than
    # reusing `smtp_username`.
    smtp_from_address: Mapped[str | None] = mapped_column(String(255), nullable=True)
    smtp_from_name: Mapped[str | None] = mapped_column(String(255), nullable=True)

    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), onupdate=func.now(), nullable=False
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"AppSettings(audit_log_retention_days={self.audit_log_retention_days!r})"
