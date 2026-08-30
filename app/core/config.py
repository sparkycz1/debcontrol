"""Application configuration.

All settings are read from the environment (12-factor app) via
pydantic-settings. Nothing sensitive should ever be hardcoded here or
committed — see `.env.example`.
"""

from __future__ import annotations

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

    # Bearer token machines must present when self-registering via POST /api/inform.
    inform_token: SecretStr = Field(alias="INFORM_TOKEN")

    # apt update/upgrade/autoremove/autoclean can legitimately take a long
    # time (large downloads, many packages) — this is the max wall-clock
    # time given to that whole sequence, distinct from `ssh_connect_timeout`
    # (which only bounds establishing the connection itself).
    update_timeout_seconds: int = Field(default=1800, alias="UPDATE_TIMEOUT_SECONDS")

    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

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


@lru_cache
def get_settings() -> Settings:
    """Settings are loaded once and cached — validation happens on first import."""
    return Settings()  # values come from the environment / .env (pydantic-settings)
