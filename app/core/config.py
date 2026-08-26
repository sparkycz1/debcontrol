"""Konfigurace aplikace.

Veškeré nastavení se čte z prostředí (12-factor app) přes pydantic-settings.
Nic citlivého se nesmí zapisovat natvrdo do kódu ani commitovat — viz `.env.example`.
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

    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

    @field_validator("secret_key", "encryption_key")
    @classmethod
    def _reject_placeholder_secrets(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value()
        if raw.startswith("change-me") or len(raw) < 16:
            raise ValueError(
                "Placeholder nebo příliš krátký secret v konfiguraci. "
                "Vygeneruj skutečnou hodnotu (viz .env.example) před spuštěním."
            )
        return value

    @property
    def is_production(self) -> bool:
        return self.app_env.lower() == "production"


@lru_cache
def get_settings() -> Settings:
    """Nastavení se načte jednou a cachuje — validace proběhne při prvním importu."""
    return Settings()  # hodnoty přichází z env/.env (pydantic-settings)
