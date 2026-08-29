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
from datetime import datetime

from sqlalchemy import Boolean, Enum, Integer, LargeBinary, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

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


class AppSettings(Base):
    __tablename__ = "app_settings"

    id: Mapped[int] = mapped_column(primary_key=True)

    # How many days of audit_log_entries to keep before the daily purge job
    # (app.tasks.jobs.purge_old_audit_log_entries) deletes them. NULL means
    # "keep forever" — the default, since silently discarding audit history
    # is a much worse surprise than an unbounded table.
    audit_log_retention_days: Mapped[int | None] = mapped_column(Integer, nullable=True)

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

    # --- Syslog forwarding of audit log entries (app.audit_syslog), e.g. to
    # a SIEM. Best-effort/fire-and-forget: the DB row is always the source
    # of truth, this is only ever a live mirror of it. ---
    syslog_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    syslog_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    syslog_port: Mapped[int] = mapped_column(Integer, default=DEFAULT_SYSLOG_PORT, nullable=False)
    syslog_protocol: Mapped[SyslogProtocol] = mapped_column(
        Enum(SyslogProtocol, name="syslog_protocol", native_enum=True),
        default=SyslogProtocol.UDP,
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), onupdate=func.now(), nullable=False
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"AppSettings(audit_log_retention_days={self.audit_log_retention_days!r})"
