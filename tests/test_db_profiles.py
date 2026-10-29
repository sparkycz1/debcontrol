"""Compose profiles for the database (0.128.0): the `migrate` precheck, the
`.env` upgrade in scripts/setup.py, and the structure of docker-compose.yml
that the automatic postgres <-> timescaledb move relies on."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from app.db import precheck
from scripts import setup

ROOT = Path(__file__).parent.parent
BUNDLED = "postgresql+asyncpg://debcontrol:pw@db:5432/debcontrol"


# --- app.db.precheck -------------------------------------------------------


def test_precheck_ignores_own_database(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(host: str) -> set[str]:
        raise AssertionError("an own database must not be resolved")

    monkeypatch.setattr(precheck, "resolve", fail)
    assert precheck.check("postgresql+asyncpg://u:p@pg.example.net:5432/dc") is None


def test_precheck_no_bundled_database(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(precheck, "resolve", lambda host: set())
    assert precheck.check(BUNDLED) == precheck.NO_DATABASE


def test_precheck_one_bundled_database(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(precheck, "resolve", lambda host: {"172.18.0.3", "fd00::3"})
    assert precheck.check(BUNDLED) is None


def test_precheck_two_bundled_databases(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(precheck, "resolve", lambda host: {"172.18.0.3", "172.18.0.4"})
    assert precheck.check(BUNDLED) == precheck.TWO_DATABASES


def test_precheck_main_prints_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(precheck, "check", lambda url: precheck.NO_DATABASE)
    assert precheck.main() == 1
    assert "COMPOSE_PROFILES" in capsys.readouterr().err


# --- scripts/setup.py ------------------------------------------------------


@pytest.mark.parametrize(
    ("database", "caddy", "expected"),
    [
        ("postgres", False, "postgres"),
        ("timescaledb", True, "timescaledb,caddy"),
        ("own", False, ""),
        ("own", True, "caddy"),
    ],
)
def test_profiles_value(database: str, caddy: bool, expected: str) -> None:
    assert setup.profiles_value(database, use_caddy=caddy) == expected


@pytest.mark.parametrize(
    ("env", "expected"),
    [
        ("POSTGRES_PASSWORD=x\n", "postgres"),
        ("POSTGRES_HOST=db\nDOMAIN=dc.example.com\n", "postgres,caddy"),
        ("POSTGRES_HOST=10.0.0.5\n", ""),
        ("DATABASE_URL=postgresql+asyncpg://u:p@db:5432/dc\nDOMAIN=\n", "postgres"),
        ("DATABASE_URL=postgresql+asyncpg://u:p@pg.lan:5432/dc\n", ""),
    ],
)
def test_ensure_profiles_on_old_env(tmp_path: Path, env: str, expected: str) -> None:
    path = tmp_path / ".env"
    path.write_text(env, encoding="utf-8")
    setup._ensure_profiles(path)
    assert setup._read_env_value(path, "COMPOSE_PROFILES") == expected


def test_ensure_profiles_keeps_existing_value(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_text("COMPOSE_PROFILES=timescaledb\n", encoding="utf-8")
    setup._ensure_profiles(path)
    assert path.read_text(encoding="utf-8") == "COMPOSE_PROFILES=timescaledb\n"


# --- docker-compose.yml ----------------------------------------------------


@pytest.fixture(scope="module")
def services() -> dict[str, Any]:
    data = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    result: dict[str, Any] = data["services"]
    return result


def test_profiles_of_optional_services(services: dict[str, Any]) -> None:
    assert services["db"]["profiles"] == ["postgres"]
    assert services["timescaledb"]["profiles"] == ["timescaledb"]
    assert services["caddy"]["profiles"] == ["caddy"]
    for always in ("redis", "migrate", "web", "worker", "beat"):
        assert "profiles" not in services[always], always


def test_timescaledb_answers_to_db(services: dict[str, Any]) -> None:
    ts = services["timescaledb"]
    assert ts["image"].startswith("timescale/timescaledb:")
    assert "db" in ts["networks"]["default"]["aliases"]
    assert ts["environment"]["TIMESCALEDB_TELEMETRY"] == "off"


def test_database_dependencies_are_optional(services: dict[str, Any]) -> None:
    for name in ("db", "timescaledb"):
        dep = services["migrate"]["depends_on"][name]
        assert dep == {"condition": "service_healthy", "required": False}
    for app in ("web", "worker", "beat"):
        deps = services[app]["depends_on"]
        assert deps["migrate"]["condition"] == "service_completed_successfully"
        for importer in ("import-from-postgres", "import-from-timescaledb"):
            assert deps[importer] == {
                "condition": "service_completed_successfully",
                "required": False,
            }


@pytest.mark.parametrize(
    ("importer", "profile", "source", "target"),
    [
        ("import-from-postgres", "timescaledb", "pg_data", "ts_data"),
        ("import-from-timescaledb", "postgres", "ts_data", "pg_data"),
    ],
)
def test_importers(
    services: dict[str, Any], importer: str, profile: str, source: str, target: str
) -> None:
    svc = services[importer]
    assert svc["profiles"] == [profile]
    assert svc["entrypoint"] == ["bash", "/db_import.sh"]
    assert f"{source}:/var/lib/postgresql" in svc["volumes"]
    assert f"{target}:/target-volume" in svc["volumes"]
    assert svc["environment"]["TARGET_HOST"] == "db"
    assert svc["depends_on"]["migrate"]["condition"] == "service_completed_successfully"


def test_migrate_runs_precheck(services: dict[str, Any]) -> None:
    assert "python -m app.db.precheck" in " ".join(services["migrate"]["command"])


def test_caddy_file_is_a_compatibility_stub() -> None:
    text = (ROOT / "docker-compose.caddy.yml").read_text(encoding="utf-8")
    assert "profiles: !reset []" in text
