"""Time column in the sample tables' primary keys; old schema drift fixed.

- machine_monitoring_samples, machine_reachability_samples and
  endpoint_check_results get (id, <time column>) as primary key, which a
  TimescaleDB hypertable requires (app/db/timescale.py). Plain PostgreSQL
  just rebuilds the key index once.
- Drift between older migrations and the models, found by `alembic check`:
  - fleet_snapshots: the redundant non-unique index next to the unique
    constraint on snapshot_date is dropped;
  - fleet_summaries.created_at and notification_conditions.rule_id keep
    their indexes (now declared in the models too, nothing to do here);
  - three timestamps stored without a time zone become timestamptz (the
    values were always written as UTC).

Revision ID: f2b4d6e8a0c1
Revises: e1a3c5e7f9b2
Create Date: 2026-10-29
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "f2b4d6e8a0c1"
down_revision: str | None = "e1a3c5e7f9b2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SAMPLE_TABLES = (
    ("machine_monitoring_samples", "sampled_at"),
    ("machine_reachability_samples", "checked_at"),
    ("endpoint_check_results", "checked_at"),
)

_NAIVE_TIMESTAMPS = (
    ("machine_update_runs", "snapshot_rolled_back_at"),
    ("machines", "host_key_changed_at"),
    ("terminal_recordings", "started_at"),
)


def upgrade() -> None:
    for table, time_column in _SAMPLE_TABLES:
        op.drop_constraint(f"pk_{table}", table, type_="primary")
        op.create_primary_key(f"pk_{table}", table, ["id", time_column])

    op.drop_index("ix_fleet_snapshots_snapshot_date", table_name="fleet_snapshots")

    for table, column in _NAIVE_TIMESTAMPS:
        op.execute(
            f"ALTER TABLE {table} ALTER COLUMN {column} "
            f"TYPE timestamp with time zone USING {column} AT TIME ZONE 'UTC'"
        )


def downgrade() -> None:
    for table, column in _NAIVE_TIMESTAMPS:
        op.execute(
            f"ALTER TABLE {table} ALTER COLUMN {column} "
            f"TYPE timestamp without time zone USING {column} AT TIME ZONE 'UTC'"
        )

    op.create_index("ix_fleet_snapshots_snapshot_date", "fleet_snapshots", ["snapshot_date"])

    for table, _time_column in _SAMPLE_TABLES:
        op.drop_constraint(f"pk_{table}", table, type_="primary")
        op.create_primary_key(f"pk_{table}", table, ["id"])
