"""Checked by the `migrate` service before `alembic upgrade head`
(`python -m app.db.precheck`): turns the two ways a Compose setup can
point at no database, or at two, into one clear message instead of a
connection error further down.

- The configured host is the bundled name `db` but nothing answers to it:
  neither database profile is on (COMPOSE_PROFILES in .env is missing,
  e.g. after updating by hand with `git pull` past 0.128.0) and no own
  database is configured.
- `db` resolves to two addresses: the bundled PostgreSQL and TimescaleDB
  are both running (both profiles on, or the one being left still runs).

Any other host is the operator's own database and is left alone. Exit
code 0 = fine, 1 = the message above was printed.
"""

from __future__ import annotations

import socket
import sys
from urllib.parse import urlsplit

from app.core.config import get_settings

BUNDLED_HOST = "db"

NO_DATABASE = (
    "No database: the host 'db' does not exist. Since 0.128.0 the bundled "
    "database is a Compose profile. Add COMPOSE_PROFILES=postgres (or "
    "timescaledb; add ,caddy if you use the bundled Caddy) to .env and run "
    "'docker compose up -d' again; scripts/upgrade.sh does this by itself. "
    "For your own PostgreSQL set POSTGRES_HOST/POSTGRES_PORT or "
    "DATABASE_URL instead. See wiki/Installation."
)
TWO_DATABASES = (
    "Two databases answer to 'db': the bundled PostgreSQL and TimescaleDB "
    "are both running. Keep only one of the profiles 'postgres' and "
    "'timescaledb' in COMPOSE_PROFILES, stop the other one (docker compose "
    "stop db, or docker compose stop timescaledb) and start again."
)


def configured_host(database_url: str) -> str | None:
    """The host part of a SQLAlchemy URL (None for a Unix socket URL)."""
    return urlsplit(database_url).hostname


def resolve(host: str) -> set[str]:
    """Every IPv4/IPv6 address `host` resolves to; empty when it doesn't."""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return set()
    return {str(info[4][0]) for info in infos}


def check(database_url: str) -> str | None:
    """The problem to report, or None when the database looks reachable."""
    host = configured_host(database_url)
    if host != BUNDLED_HOST:
        return None
    addresses = resolve(host)
    if not addresses:
        return NO_DATABASE
    if len({a for a in addresses if ":" not in a}) > 1:
        return TWO_DATABASES
    return None


def main() -> int:
    problem = check(get_settings().database_url)
    if problem:
        print(f"error: {problem}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
