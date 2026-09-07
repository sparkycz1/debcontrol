"""Application configuration.

All settings are read from the environment (12-factor app) via
pydantic-settings. Nothing sensitive should ever be hardcoded here or
committed — see `.env.example`.
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache
from pathlib import Path
from urllib.parse import quote

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_env: str = Field(default="development", alias="APP_ENV")
    secret_key: SecretStr = Field(alias="SECRET_KEY")
    encryption_key: SecretStr = Field(alias="ENCRYPTION_KEY")

    # --- PostgreSQL ---
    # `database_url` is built from these parts if not set explicitly, so the
    # password only has to be written once. Set `database_url` directly
    # instead if you need something these parts can't express (a different
    # driver, extra connection options, a managed DB with its own auth).
    postgres_user: str = Field(default="debcontrol", alias="POSTGRES_USER")
    postgres_password: SecretStr = Field(alias="POSTGRES_PASSWORD")
    postgres_db: str = Field(default="debcontrol", alias="POSTGRES_DB")
    # Defaults match the docker-compose service name — override for a local,
    # non-Docker Postgres (e.g. "localhost").
    postgres_host: str = Field(default="db", alias="POSTGRES_HOST")
    postgres_port: int = Field(default=5432, alias="POSTGRES_PORT")
    database_url_override: str | None = Field(default=None, alias="DATABASE_URL")

    # SQLAlchemy async engine pool sizing for the **web** process only — see
    # app/db/session.py. (The Celery worker's own per-child engine uses
    # NullPool instead, for a different reason entirely: see
    # app/tasks/celery_app.py's `_init_worker_process`.) SQLAlchemy's own
    # defaults (5/10) are conservative for a low-traffic single-admin
    # deployment; a fleet in the hundreds/thousands with several admins each
    # keeping machine/dashboard pages open (which self-poll every 20-30s,
    # see wiki/Architecture.md) benefits from a larger pool. Postgres'
    # `max_connections` (default 100) must comfortably exceed
    # `db_pool_size + db_max_overflow` plus whatever the worker/beat/migrate
    # services need at once — see wiki/Host-Requirements.md.
    db_pool_size: int = Field(default=10, alias="DB_POOL_SIZE")
    db_max_overflow: int = Field(default=20, alias="DB_MAX_OVERFLOW")

    # --- Redis (Celery broker + result backend, and the login rate limiter) ---
    # Same pattern as Postgres above: `redis_url` is built from these parts
    # unless set explicitly.
    redis_password: SecretStr = Field(alias="REDIS_PASSWORD")
    redis_host: str = Field(default="redis", alias="REDIS_HOST")
    redis_port: int = Field(default=6379, alias="REDIS_PORT")
    redis_db: int = Field(default=0, alias="REDIS_DB")
    redis_url_override: str | None = Field(default=None, alias="REDIS_URL")

    ssh_data_dir: Path = Field(default=Path("./data"), alias="SSH_DATA_DIR")
    ssh_connect_timeout: int = Field(default=10, alias="SSH_CONNECT_TIMEOUT")

    # How often (seconds) the background worker re-checks OS/kernel/hostname/
    # CPU/RAM/disk facts for every machine.
    facts_refresh_interval_seconds: int = Field(
        default=3600, alias="FACTS_REFRESH_INTERVAL_SECONDS"
    )

    # How often (seconds) the "is it alive" status badge's reachability sweep
    # (a plain TCP connect to the SSH port, no authentication) runs for every
    # machine. Deliberately its own, much shorter, default than
    # `facts_refresh_interval_seconds` — this check is cheap enough to run
    # far more often.
    reachability_check_interval_seconds: int = Field(
        default=60, alias="REACHABILITY_CHECK_INTERVAL_SECONDS"
    )

    # How often (seconds) the Monitoring tab's CPU/RAM/disk-usage sample (and
    # the cheap "how many systemd services are failed" count shown there) is
    # taken for every machine — a real SSH round trip (unlike the plain TCP
    # reachability check above), but much lighter than a full facts refresh.
    # Its own cadence, deliberately between the other two: frequent enough
    # for a useful trend graph, not so frequent it dominates worker capacity
    # at fleet scale (see wiki/Host-Requirements.md). A machine can raise
    # its own interval via `Machine.monitoring_interval_seconds` — see
    # `app.tasks.jobs._due_machines`, the same mechanism
    # `reachability_check_interval_seconds`/`facts_refresh_interval_seconds`
    # already use.
    monitoring_interval_seconds: int = Field(default=120, alias="MONITORING_INTERVAL_SECONDS")

    # How many machines the reachability sweep (app.tasks.jobs._ping_all_machines)
    # checks concurrently — a semaphore, not a thread/process count, since
    # each check is just an `asyncio` TCP connect attempt. The default (20)
    # comfortably finishes one sweep of a few hundred machines well within
    # the default 60s interval; a fleet in the thousands needs this raised
    # (see wiki/Host-Requirements.md) so one sweep reliably finishes
    # before the next one is due — Beat does not skip/coalesce a sweep that's
    # still running when its next tick fires, so a sweep that consistently
    # overruns the interval means overlapping sweeps piling up over time.
    reachability_check_concurrency: int = Field(
        default=20, alias="REACHABILITY_CHECK_CONCURRENCY"
    )

    # Bearer token machines must present when self-registering via POST /api/inform.
    inform_token: SecretStr = Field(alias="INFORM_TOKEN")

    # apt update/upgrade/autoremove/autoclean can legitimately take a long
    # time (large downloads, many packages) — this is the max wall-clock
    # time given to that whole sequence, distinct from `ssh_connect_timeout`
    # (which only bounds establishing the connection itself).
    update_timeout_seconds: int = Field(default=1800, alias="UPDATE_TIMEOUT_SECONDS")

    # Comma-separated absolute path prefixes the Logs tab's "view an
    # arbitrary file" feature is allowed to read from a managed machine
    # (app.ssh.logs.is_path_allowed) — a UX/scope guardrail for an admin who
    # already has `action.terminal` (who could read the same file directly
    # in the terminal anyway), not a hard security boundary against that
    # account itself. Default covers the journal's usual on-disk location
    # plus the conventional log directory; add more (e.g. an app's own log
    # dir outside /var/log) as needed.
    log_file_allowed_paths: str = Field(
        default="/var/log,/var/lib/docker/containers", alias="LOG_FILE_ALLOWED_PATHS"
    )

    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

    # Replace the built-in icon+wordmark (header, favicon, login page) with
    # your own branding — each value is either a URL (http(s):// or a
    # data: URI, used as-is) or a local filesystem path this app reads and
    # serves itself (mount it into the container, e.g. via a Docker
    # volume) — see app.web.branding for exactly how a value is told
    # apart, and app/web/routes/branding.py for the routes a local path is
    # served at. Unset (default) keeps the built-in default for either.
    custom_logo: str | None = Field(default=None, alias="CUSTOM_LOGO")
    custom_favicon: str | None = Field(default=None, alias="CUSTOM_FAVICON")

    # Which reverse proxies to trust `X-Forwarded-Proto` from, for deriving
    # the *scheme* (http/https, ws/wss) a request actually arrived as —
    # nothing else (host/port already come through correctly from a
    # forwarded Host header, which every reverse proxy passes through
    # untouched by default). Without this, a TLS-terminating proxy leaves
    # the app seeing plain "http" for every request no matter what the
    # browser actually used, which breaks WebAuthn/passkeys (the verified
    # origin has to match exactly what the browser sent) and OIDC login
    # (the redirect_uri built from the request would have the wrong
    # scheme). Comma-separated IPs/CIDRs, or the default "*" to trust any
    # peer — safe here even from an untrusted direct client, since the
    # only things derived from the corrected scheme are values a forged
    # header can only cause to *mismatch* a cryptographic check elsewhere
    # (WebAuthn's browser-signed origin, an OIDC provider's own registered
    # redirect_uri) and fail closed, never one it can forge a match for.
    # Narrow this to your actual proxy's IP/subnet if you'd rather not rely
    # on that reasoning. See app.core.proxy_headers.
    trusted_proxy_ips: str = Field(default="*", alias="TRUSTED_PROXY_IPS")

    @property
    def trust_all_proxies(self) -> bool:
        return self.trusted_proxy_ips.strip() == "*"

    @property
    def trusted_proxy_networks(
        self,
    ) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        """Parsed `trusted_proxy_ips` as `ipaddress` networks — empty when
        `trust_all_proxies` is True (that case is checked separately, since
        "*" isn't a valid network literal). A bare IP (no `/prefix`) is
        accepted via `ip_network(..., strict=False)`, same as a /32 or /128."""
        if self.trust_all_proxies:
            return []
        networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for part in self.trusted_proxy_ips.split(","):
            part = part.strip()
            if not part:
                continue
            networks.append(ipaddress.ip_network(part, strict=False))
        return networks

    # Whether to also trust `X-Forwarded-For` from a `trusted_proxy_ips`
    # peer, to correct `request.client.host` (the audit log's `ip_address`
    # column, and the login/TOTP rate limiter's per-source bucket key —
    # app/auth/rate_limit.py) to the real client behind a reverse proxy
    # instead of the proxy's own address. Off by default, unlike scheme
    # trust above: this one *is* a real risk to default on — a client that
    # can set an arbitrary X-Forwarded-For on each request (true of anyone
    # reaching this app directly, bypassing your real proxy, e.g. if this
    # app's port is also exposed) could make every login/TOTP attempt look
    # like a different source and defeat the rate limiter entirely if this
    # were trusted from just anyone. Turn this on only once you've also
    # narrowed `TRUSTED_PROXY_IPS` above to your actual proxy's own
    # address/subnet (not the default "*") — see app.core.proxy_headers.
    trust_forwarded_for: bool = Field(default=False, alias="TRUST_FORWARDED_FOR")

    # IANA timezone name (e.g. "Europe/Prague") the UI renders timestamps
    # in — audit log entries, "last refreshed"/"last run" times, etc.
    # Falls back to UTC if unset or not a recognized zone. Data is always
    # stored in Postgres as UTC regardless of this, and Scheduling's cron
    # expressions are always interpreted as UTC regardless of this too —
    # only display formatting is affected. The same variable also sets
    # every container's own OS timezone (see docker-compose.yml).
    tz: str = Field(default="UTC", alias="TZ")

    @field_validator("secret_key", "encryption_key", "inform_token")
    @classmethod
    def _reject_placeholder_secrets(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value()
        if raw.startswith("change-me") or len(raw) < 16:
            raise ValueError(
                "Placeholder or too-short secret in configuration. "
                "Generate a real value (see .env.example) before starting the app."
            )
        return value

    @property
    def database_url(self) -> str:
        """`DATABASE_URL` if set directly, otherwise built from the
        `postgres_*` parts so the password is only written once in `.env`.
        The password is percent-encoded (`quote`, `safe=""`) since a raw
        `@`, `/`, or `:` in it would otherwise be parsed as URL structure,
        not part of the credential."""
        if self.database_url_override is not None:
            return self.database_url_override
        password = quote(self.postgres_password.get_secret_value(), safe="")
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def redis_url(self) -> str:
        """Same pattern as `database_url` above, built from the `redis_*` parts."""
        if self.redis_url_override is not None:
            return self.redis_url_override
        password = quote(self.redis_password.get_secret_value(), safe="")
        return f"redis://:{password}@{self.redis_host}:{self.redis_port}/{self.redis_db}"

    @property
    def is_production(self) -> bool:
        return self.app_env.lower() == "production"

    @property
    def log_file_allowed_path_list(self) -> list[str]:
        """`log_file_allowed_paths` split and cleaned up — empty entries
        (e.g. a trailing comma) dropped, no trailing slash (so a prefix
        check via `str.startswith` doesn't require the caller to normalize
        first)."""
        return [
            part.strip().rstrip("/")
            for part in self.log_file_allowed_paths.split(",")
            if part.strip()
        ]


@lru_cache
def get_settings() -> Settings:
    """Settings are loaded once and cached — validation happens on first import."""
    return Settings()  # values come from the environment / .env (pydantic-settings)
