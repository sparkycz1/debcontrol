"""Application configuration.

All settings are read from the environment (12-factor app) via
pydantic-settings. Nothing sensitive should ever be hardcoded here or
committed — see `.env.example`.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

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

    database_url: str = Field(alias="DATABASE_URL")
    redis_url: str = Field(alias="REDIS_URL")

    ssh_data_dir: Path = Field(default=Path("./data"), alias="SSH_DATA_DIR")
    ssh_connect_timeout: int = Field(default=10, alias="SSH_CONNECT_TIMEOUT")

    # How often (seconds) the background worker re-checks OS/kernel/hostname/
    # CPU/RAM/disk facts for every machine. The per-minute reachability check
    # (the "is it alive" status badge) is intentionally fixed, not configurable.
    facts_refresh_interval_seconds: int = Field(
        default=3600, alias="FACTS_REFRESH_INTERVAL_SECONDS"
    )

    # Bearer token machines must present when self-registering via POST /api/inform.
    inform_token: SecretStr = Field(alias="INFORM_TOKEN")

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
    def is_production(self) -> bool:
        return self.app_env.lower() == "production"


@lru_cache
def get_settings() -> Settings:
    """Settings are loaded once and cached — validation happens on first import."""
    return Settings()  # values come from the environment / .env (pydantic-settings)
