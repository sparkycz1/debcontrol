"""app.core.config.Settings — building DATABASE_URL/REDIS_URL from parts.

See app/core/config.py's module/field docstrings for why: the password
should only need to be written once in `.env`, not once bare and again
embedded in a URL.
"""

from __future__ import annotations

import pytest

from app.core.config import Settings

_BASE_ENV = {
    "SECRET_KEY": "test-only-secret-key-not-for-real-use-000000",
    "ENCRYPTION_KEY": "IYH8EiMlmjkDacPXmvWQgDjTojLMD6GDwD8STyL1x0Y=",
    "INFORM_TOKEN": "test-only-inform-token-not-for-real-use-000000",
}


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Base required settings, with DATABASE_URL/REDIS_URL cleared so the
    from-parts path actually runs instead of an override some other
    fixture (or conftest's module-level os.environ.setdefault) already set."""
    for key, value in _BASE_ENV.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("REDIS_URL", raising=False)


def test_database_url_is_built_from_postgres_parts(
    clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("POSTGRES_PASSWORD", "hunter2")
    monkeypatch.setenv("REDIS_PASSWORD", "hunter2")
    settings = Settings()
    assert settings.database_url == "postgresql+asyncpg://debcontrol:hunter2@db:5432/debcontrol"


def test_redis_url_is_built_from_redis_parts(
    clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("POSTGRES_PASSWORD", "hunter2")
    monkeypatch.setenv("REDIS_PASSWORD", "hunter2")
    settings = Settings()
    assert settings.redis_url == "redis://:hunter2@redis:6379/0"


def test_built_urls_percent_encode_special_characters(
    clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A raw `@`, `/`, or `:` in the password would otherwise be parsed as
    URL structure rather than part of the credential."""
    monkeypatch.setenv("POSTGRES_PASSWORD", "p@ss/word:1")
    monkeypatch.setenv("REDIS_PASSWORD", "p@ss/word:1")
    settings = Settings()
    assert settings.database_url == (
        "postgresql+asyncpg://debcontrol:p%40ss%2Fword%3A1@db:5432/debcontrol"
    )
    assert settings.redis_url == "redis://:p%40ss%2Fword%3A1@redis:6379/0"


def test_explicit_database_url_overrides_the_built_one(
    clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("POSTGRES_PASSWORD", "hunter2")
    monkeypatch.setenv("REDIS_PASSWORD", "hunter2")
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://custom:pw@managed-host/mydb")
    settings = Settings()
    assert settings.database_url == "postgresql+asyncpg://custom:pw@managed-host/mydb"


def test_postgres_host_and_port_are_overridable(
    clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("POSTGRES_PASSWORD", "hunter2")
    monkeypatch.setenv("REDIS_PASSWORD", "hunter2")
    monkeypatch.setenv("POSTGRES_HOST", "localhost")
    monkeypatch.setenv("POSTGRES_PORT", "5433")
    settings = Settings()
    assert settings.database_url == "postgresql+asyncpg://debcontrol:hunter2@localhost:5433/debcontrol"
