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

from sqlalchemy import Boolean, ForeignKey, Integer, LargeBinary, String, Text, func
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
DEFAULT_GEOIP_REFRESH_INTERVAL_HOURS = 168


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
    # (app.tasks.jobs.purge_old_audit_log_entries) deletes them. NULL still
    # means "keep forever" if an operator wants that — but the default is a
    # bounded 90 days, same as the operational-data retention settings below,
    # rather than unbounded: a real fleet's audit trail otherwise grows
    # forever with nothing here to bound it, and 90 days is long enough to
    # cover almost any investigation window while still being an explicit,
    # visible choice on the Settings page (not a silent app-side default
    # someone has to go looking for).
    audit_log_retention_days: Mapped[int | None] = mapped_column(
        Integer, nullable=True, default=90
    )

    # --- Sign-in policy (Settings -> Security, see app.auth.session_policy).
    # Defaults are the values that used to be hardcoded in app.auth.sessions
    # and app.auth.login, so an upgrading instance behaves identically until
    # an admin changes one. ---
    #
    # A session with no request for this long expires (sliding window).
    session_idle_timeout_minutes: Mapped[int] = mapped_column(
        Integer, default=720, nullable=False
    )
    # ...and every session ends this long after sign-in, however active.
    session_absolute_max_hours: Mapped[int] = mapped_column(
        Integer, default=720, nullable=False
    )
    # Consecutive failed sign-ins (password or second factor) that lock an
    # account, and for how long — app.auth.login._register_failed_attempt.
    login_max_failed_attempts: Mapped[int] = mapped_column(Integer, default=5, nullable=False)
    login_lockout_minutes: Mapped[int] = mapped_column(Integer, default=15, nullable=False)
    # Newline/comma-separated IPs or CIDR networks the web UI and the REST
    # API accept requests from; NULL/empty = anywhere. Checked against the
    # client address as resolved by app.core.proxy_headers.
    login_allowed_networks: Mapped[str | None] = mapped_column(Text, nullable=True)

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

    # Same idea again, for `NotificationLog` rows (app.tasks.jobs.
    # purge_old_notification_logs) — one row per actual send attempt (per
    # recipient for email, per rule for webhook), which on a large fleet
    # with frequent condition-based rules can accumulate quickly. This is
    # delivery history for troubleshooting ("did that alert actually go
    # out"), not the audit-worthy fact itself (that already has its own
    # `notification_rule.*` audit entries with their own retention), so it
    # defaults to a bounded window (90 days) for the same reason
    # dashboard_trends_retention_days does. NULL still means "keep forever."
    notification_log_retention_days: Mapped[int | None] = mapped_column(
        Integer, nullable=True, default=90
    )

    # --- Background checks (moved here from environment variables — see
    # app.core.config's module docstring and wiki/Development.md's
    # "Settings vs. environment" note). Defaults match what used to be the
    # hardcoded env defaults, so an upgrading instance behaves identically
    # until an admin changes one from the new Settings → Monitoring tab. ---
    #
    # How long (seconds) a single SSH connection attempt is given before
    # giving up — see app.ssh.connection. Read fresh from this table on
    # every task run (app.tasks.jobs), so a change here takes effect on the
    # very next scheduled check, no restart needed.
    ssh_connect_timeout: Mapped[int] = mapped_column(Integer, default=10, nullable=False)
    # Max wall-clock time given to one apt/flatpak/snap update run (distinct
    # from ssh_connect_timeout, which only bounds establishing the
    # connection itself). Celery's own hard per-task time limit for the
    # update-run tasks is a separate, generous, code-level constant (see
    # app.tasks.jobs._UPDATE_TASK_TIME_LIMIT_SECONDS) sized to comfortably
    # exceed any value this field can be set to — that constant is a Celery
    # process-safety ceiling, not something an operator tunes; this field is
    # the actual, meaningful timeout.
    update_timeout_seconds: Mapped[int] = mapped_column(Integer, default=1800, nullable=False)
    # How often (seconds) the background worker re-checks OS/kernel/
    # hostname/CPU/RAM/disk facts, packages, services, and readiness for
    # every machine. Beat re-reads this only at its own process start (see
    # app.tasks.celery_app) — same "restart to pick up a change" contract
    # this field had back when it was FACTS_REFRESH_INTERVAL_SECONDS in .env.
    facts_refresh_interval_seconds: Mapped[int] = mapped_column(
        Integer, default=3600, nullable=False
    )
    # How often (seconds) the "is it alive" status badge's reachability
    # sweep runs for every machine. Same Beat-restart caveat as above.
    reachability_check_interval_seconds: Mapped[int] = mapped_column(
        Integer, default=60, nullable=False
    )
    # How often (seconds) the Monitoring tab's CPU/RAM/disk-usage sample is
    # taken for every machine. Same Beat-restart caveat as above.
    monitoring_interval_seconds: Mapped[int] = mapped_column(
        Integer, default=120, nullable=False
    )
    # How many machines the reachability sweep checks concurrently — a
    # semaphore, not a thread/process count. Read fresh from this table on
    # every sweep (app.tasks.jobs._ping_all_machines), so this one *does*
    # take effect immediately, unlike the three interval fields above.
    reachability_check_concurrency: Mapped[int] = mapped_column(
        Integer, default=20, nullable=False
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

    # Thins out `MachineMonitoringSample` rows older than this many days,
    # keeping only the first sample in each `monitoring_downsample_interval_
    # minutes`-wide bucket per machine and deleting the rest — see
    # `app.tasks.jobs.downsample_old_monitoring_samples`. A chart's own
    # display-side bucketing already coarsens old data down to a handful of
    # points before it's ever drawn (`app.services.monitoring_history.
    # _bucket_average`), so keeping every raw sample from months ago costs
    # storage for resolution nothing renders. NULL disables downsampling
    # entirely (every sample kept at full resolution until the retention
    # purge above deletes it outright); default keeps a week at full
    # resolution before thinning starts.
    monitoring_downsample_after_days: Mapped[int | None] = mapped_column(
        Integer, nullable=True, default=7
    )
    monitoring_downsample_interval_minutes: Mapped[int] = mapped_column(
        Integer, default=60, nullable=False
    )

    # How often (seconds) condition-based notification rules (CPU/RAM/
    # disk/etc. thresholds — see app.db.models.notification_condition and
    # app.services.notifications) are re-evaluated against the fleet's
    # latest facts/monitoring data. Same Beat-restart caveat as the other
    # interval fields above.
    notification_condition_check_interval_seconds: Mapped[int] = mapped_column(
        Integer, default=60, nullable=False
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

    # --- GeoIP lookups (app.services.geoip) — resolves a public source IP
    # to a country/city/lat-long, once at audit-log write time
    # (app.audit.log_event), from a MaxMind-DB-format (.mmdb) database this
    # app downloads itself and caches in `GeoipDatabase`. Never bundled —
    # MaxMind's GeoLite2 license forbids redistribution. The URLs are
    # encrypted at rest like every other secret here: a MaxMind
    # "permalink" download URL embeds a license key. ---
    geoip_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    geoip_primary_url_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    geoip_backup_url_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    # Matches MaxMind's own GeoLite2 update cadence (weekly).
    geoip_refresh_interval_hours: Mapped[int] = mapped_column(
        Integer, default=DEFAULT_GEOIP_REFRESH_INTERVAL_HOURS, nullable=False
    )

    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), onupdate=func.now(), nullable=False
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"AppSettings(audit_log_retention_days={self.audit_log_retention_days!r})"
