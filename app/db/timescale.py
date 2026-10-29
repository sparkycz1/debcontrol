"""TimescaleDB, when the database has it (the bundled `timescaledb` Compose
profile, or an own PostgreSQL with `CREATE EXTENSION timescaledb`).

Nothing here changes the schema Alembic manages: the same tables exist on
PostgreSQL and TimescaleDB, so data moves freely between the two
(scripts/db_import.sh). On TimescaleDB this module adds, idempotently:

- the three history tables as hypertables with one-day chunks;
- compression (TimescaleDB's columnstore) of chunks older than 7 days,
  segmented by machine/check — the monitoring samples wait one day past
  the downsampling age when downsampling is on, so a chunk is thinned out
  before it is compressed;
- two daily continuous aggregates of the availability history
  (`reachability_daily`, `endpoint_check_daily`) for the status page.

`python -m app.db.timescale` runs it in the `migrate` service after
`alembic upgrade head` (a no-op without TimescaleDB); the daily
downsampling job re-applies the compression ages when the settings changed.
Retention stays the app's own (Settings, per machine): the purge job drops
whole chunks where every machine's retention allows it
(`drop_old_chunks`) and deletes the rest row by row as on PostgreSQL.
"""

from __future__ import annotations

import asyncio
import logging
import sys
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession, create_async_engine

log = logging.getLogger(__name__)

CHUNK_INTERVAL = "1 day"
COMPRESS_AFTER_DAYS = 7
# AppSettings.monitoring_downsample_after_days' default.
DEFAULT_DOWNSAMPLE_AFTER_DAYS = 7


@dataclass(frozen=True)
class Hypertable:
    table: str
    time_column: str
    segment_by: str


MONITORING = Hypertable("machine_monitoring_samples", "sampled_at", "machine_id")
REACHABILITY = Hypertable("machine_reachability_samples", "checked_at", "machine_id")
ENDPOINT_RESULTS = Hypertable("endpoint_check_results", "checked_at", "check_id")
HYPERTABLES = (MONITORING, REACHABILITY, ENDPOINT_RESULTS)

REACHABILITY_DAILY = "reachability_daily"
ENDPOINT_CHECK_DAILY = "endpoint_check_daily"

# name -> (source hypertable, defining query). Days are UTC, like
# date(checked_at) on the PostgreSQL path of the status page.
CONTINUOUS_AGGREGATES: dict[str, tuple[Hypertable, str]] = {
    REACHABILITY_DAILY: (
        REACHABILITY,
        "SELECT machine_id, time_bucket(INTERVAL '1 day', checked_at) AS day, "
        "count(*) AS total, count(*) FILTER (WHERE reachable) AS up "
        "FROM machine_reachability_samples GROUP BY machine_id, day",
    ),
    ENDPOINT_CHECK_DAILY: (
        ENDPOINT_RESULTS,
        "SELECT check_id, time_bucket(INTERVAL '1 day', checked_at) AS day, "
        "count(*) AS total, count(*) FILTER (WHERE ok) AS up "
        "FROM endpoint_check_results GROUP BY check_id, day",
    ),
}

_EXTENSION_SQL = text("SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb')")

# Per process: whether the database has TimescaleDB. Computed on first use
# (after the fork, so every worker child asks once); the stack restarts
# whenever the database changes.
_enabled: bool | None = None


def reset_cache() -> None:
    global _enabled
    _enabled = None


async def enabled(session: AsyncSession) -> bool:
    """Whether this database has the TimescaleDB extension."""
    global _enabled
    if _enabled is None:
        if session.get_bind().dialect.name != "postgresql":
            _enabled = False
        else:
            _enabled = bool(await session.scalar(_EXTENSION_SQL))
    return _enabled


def compress_after_days(table: Hypertable, downsample_after_days: int | None) -> int:
    """Age of a chunk before it is compressed. The monitoring samples are
    downsampled first: with downsampling at N >= 7 days, they compress at
    N + 1 days, so the nightly downsampling has run over a chunk before."""
    if (
        table is MONITORING
        and downsample_after_days
        and downsample_after_days >= COMPRESS_AFTER_DAYS
    ):
        return downsample_after_days + 1
    return COMPRESS_AFTER_DAYS


async def _scalar(conn: AsyncConnection | AsyncSession, sql: str, **params: Any) -> Any:
    return (await conn.execute(text(sql), params)).scalar()


async def _ensure_hypertable(conn: AsyncConnection, table: Hypertable) -> bool:
    """Make `table` a hypertable (moving existing rows into chunks).
    Returns whether it was converted now."""
    exists = await _scalar(
        conn,
        "SELECT 1 FROM timescaledb_information.hypertables "
        "WHERE hypertable_schema = 'public' AND hypertable_name = :t",
        t=table.table,
    )
    if exists:
        return False
    await conn.execute(
        text(
            f"SELECT create_hypertable('public.{table.table}', "
            f"by_range('{table.time_column}', INTERVAL '{CHUNK_INTERVAL}'), "
            "migrate_data => true, create_default_indexes => false)"
        )
    )
    return True


async def _ensure_compression(conn: AsyncConnection | AsyncSession, table: Hypertable) -> None:
    enabled_now = await _scalar(
        conn,
        "SELECT compression_enabled FROM timescaledb_information.hypertables "
        "WHERE hypertable_schema = 'public' AND hypertable_name = :t",
        t=table.table,
    )
    if enabled_now:
        return
    await conn.execute(
        text(
            f"ALTER TABLE public.{table.table} SET ("
            "timescaledb.enable_columnstore = true, "
            f"timescaledb.segmentby = '{table.segment_by}', "
            f"timescaledb.orderby = '{table.time_column} DESC')"
        )
    )


async def apply_compression_policy(
    conn: AsyncConnection | AsyncSession, table: Hypertable, days: int
) -> bool:
    """Compress `table`'s chunks once older than `days`. Returns whether
    the policy changed."""
    current = await _scalar(
        conn,
        "SELECT config->>'compress_after' FROM timescaledb_information.jobs "
        "WHERE proc_name = 'policy_compression' AND hypertable_schema = 'public' "
        "AND hypertable_name = :t",
        t=table.table,
    )
    wanted = f"{days} days"
    if current == wanted:
        return False
    if current is not None:
        await conn.execute(text(f"CALL remove_columnstore_policy('public.{table.table}')"))
    await conn.execute(
        text(
            f"CALL add_columnstore_policy('public.{table.table}', "
            f"after => INTERVAL '{days} days')"
        )
    )
    return True


async def _ensure_continuous_aggregate(
    conn: AsyncConnection, name: str, query: str
) -> bool:
    """Create the continuous aggregate `name` with its refresh policy.
    Returns whether it was created now (and needs a first full refresh)."""
    exists = await _scalar(
        conn,
        "SELECT 1 FROM timescaledb_information.continuous_aggregates "
        "WHERE view_schema = 'public' AND view_name = :n",
        n=name,
    )
    if exists:
        return False
    await conn.execute(
        text(
            f"CREATE MATERIALIZED VIEW public.{name} WITH ("
            "timescaledb.continuous, timescaledb.materialized_only = false, "
            f"timescaledb.chunk_interval = '{CHUNK_INTERVAL}') "
            f"AS {query} WITH NO DATA"
        )
    )
    # Every hour, the last three days (late or corrected samples); older
    # days are final. Rows newer than the last refresh are added at query
    # time (materialized_only = false).
    await conn.execute(
        text(
            f"SELECT add_continuous_aggregate_policy('public.{name}', "
            "start_offset => INTERVAL '3 days', end_offset => INTERVAL '1 hour', "
            "schedule_interval => INTERVAL '1 hour', if_not_exists => true)"
        )
    )
    return True


async def _downsample_after_days(conn: AsyncConnection) -> int | None:
    """The setting (None = downsampling off); its default before the
    settings row exists (a new database)."""
    row = (
        await conn.execute(
            text("SELECT monitoring_downsample_after_days FROM app_settings ORDER BY id LIMIT 1")
        )
    ).first()
    if row is None:
        return DEFAULT_DOWNSAMPLE_AFTER_DAYS
    return int(row[0]) if row[0] is not None else None


async def setup(conn: AsyncConnection) -> list[str]:
    """Bring a TimescaleDB database to the layout above. `conn` must be in
    autocommit mode (continuous aggregates are refreshed outside a
    transaction). Returns what was done, for the log; empty when nothing
    was needed or the database has no TimescaleDB."""
    if not await _scalar(conn, _EXTENSION_SQL.text):
        return []
    done: list[str] = []
    downsample_after = await _downsample_after_days(conn)
    for table in HYPERTABLES:
        if await _ensure_hypertable(conn, table):
            done.append(f"{table.table}: hypertable")
        await _ensure_compression(conn, table)
        days = compress_after_days(table, downsample_after)
        if await apply_compression_policy(conn, table, days):
            done.append(f"{table.table}: compressed after {days} days")
    for name, (_source, query) in CONTINUOUS_AGGREGATES.items():
        if await _ensure_continuous_aggregate(conn, name, query):
            await conn.execute(
                text(f"CALL refresh_continuous_aggregate('public.{name}', NULL, NULL)")
            )
            done.append(f"{name}: continuous aggregate")
    return done


async def apply_policies(session: AsyncSession, downsample_after_days: int | None) -> None:
    """Re-apply the compression ages after a settings change (called by the
    daily downsampling job). No-op without TimescaleDB."""
    if not await enabled(session):
        return
    changed = False
    for table in HYPERTABLES:
        exists = await _scalar(
            session,
            "SELECT 1 FROM timescaledb_information.hypertables "
            "WHERE hypertable_schema = 'public' AND hypertable_name = :t",
            t=table.table,
        )
        if exists:
            days = compress_after_days(table, downsample_after_days)
            changed = await apply_compression_policy(session, table, days) or changed
    if changed:
        await session.commit()


async def describe(session: AsyncSession) -> dict[str, Any] | None:
    """What the Settings page and `GET /api/v1/settings` show: the
    extension's version and each history table's compression age (None
    when the database has no TimescaleDB)."""
    if not await enabled(session):
        return None
    version = await _scalar(
        session, "SELECT extversion FROM pg_extension WHERE extname = 'timescaledb'"
    )
    rows = await session.execute(
        text(
            "SELECT hypertable_name, config->>'compress_after' FROM timescaledb_information.jobs "
            "WHERE proc_name = 'policy_compression' AND hypertable_schema = 'public'"
        )
    )
    compress_after = {}
    for name, value in rows.all():
        days = str(value or "").split(" ", 1)[0]
        compress_after[name] = int(days) if days.isdigit() else None
    return {"version": version, "compress_after_days": compress_after}


async def refresh_aggregates(session: AsyncSession) -> None:
    """Rebuild the daily aggregates from scratch, after the history was
    replaced wholesale (a restore). Ends the session's transaction first:
    a refresh can't run inside one. No-op without TimescaleDB."""
    if not await enabled(session):
        return
    await session.commit()
    conn = await session.connection(execution_options={"isolation_level": "AUTOCOMMIT"})
    for name in CONTINUOUS_AGGREGATES:
        await conn.execute(text(f"CALL refresh_continuous_aggregate('public.{name}', NULL, NULL)"))
    await session.commit()


async def drop_old_chunks(session: AsyncSession, relation: str, older_than: datetime) -> int:
    """Drop `relation`'s chunks (a hypertable or a continuous aggregate)
    that hold only rows older than `older_than`. Returns how many went."""
    result = await session.execute(
        text(
            "SELECT count(*) FROM drop_chunks(CAST(:r AS regclass), "
            "older_than => CAST(:t AS timestamptz))"
        ),
        {"r": f"public.{relation}", "t": older_than},
    )
    await session.commit()
    return int(result.scalar() or 0)


async def _main() -> int:
    from app.core.config import get_settings

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    engine = create_async_engine(get_settings().database_url, isolation_level="AUTOCOMMIT")
    try:
        async with engine.connect() as conn:
            if conn.dialect.name != "postgresql":
                return 0
            for line in await setup(conn):
                log.info("timescaledb: %s", line)
    finally:
        await engine.dispose()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(_main()))
