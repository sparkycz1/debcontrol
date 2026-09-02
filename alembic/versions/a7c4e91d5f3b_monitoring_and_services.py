"""Monitoring tab: CPU/RAM/disk-usage history + systemd service snapshot

Revision ID: a7c4e91d5f3b
Revises: f3a91c5d0e2b
Create Date: 2026-09-02

New per-machine columns:
- `os_id`: `/etc/os-release`'s `ID=` field, for the OS logo lookup.
- `monitoring_interval_seconds`/`monitoring_history_retention_days`:
  per-machine overrides of `MONITORING_INTERVAL_SECONDS` (`.env`) and
  `AppSettings.monitoring_history_retention_days` (Settings page),
  mirroring the `reachability_check_interval_seconds`/
  `facts_refresh_interval_seconds` overrides added in f3a91c5d0e2b.
- `monitoring_updated_at`/`services_updated_at`: cache columns for
  due-filtering (`app.tasks.jobs._due_machines`) and "last refreshed"
  display, mirroring `last_ping_at`/`facts_updated_at`/`packages_updated_at`.

New `AppSettings.monitoring_history_retention_days` — the global default
the per-machine override above falls back to, same pattern as
`machine_update_run_retention_days`.

Two new tables:
- `machine_services`: a replaced snapshot (like `machine_packages`) of
  every systemd service unit, refreshed on the facts cadence.
- `machine_monitoring_samples`: a genuine history (not replaced) of
  CPU/RAM/disk-usage samples, one row per machine per monitoring tick,
  purged per-machine by `app.tasks.jobs.purge_old_monitoring_samples`.

All nullable, no backfill needed.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a7c4e91d5f3b"
down_revision: str | None = "f3a91c5d0e2b"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column("machines", sa.Column("os_id", sa.String(length=64), nullable=True))
    op.add_column(
        "machines", sa.Column("monitoring_interval_seconds", sa.Integer(), nullable=True)
    )
    op.add_column(
        "machines",
        sa.Column("monitoring_history_retention_days", sa.Integer(), nullable=True),
    )
    op.add_column(
        "machines", sa.Column("monitoring_updated_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column(
        "machines", sa.Column("services_updated_at", sa.DateTime(timezone=True), nullable=True)
    )

    op.add_column(
        "app_settings",
        sa.Column(
            "monitoring_history_retention_days", sa.Integer(), nullable=True, server_default="90"
        ),
    )
    # `server_default` only needed to backfill the existing single row
    # without a NULL — drop it afterwards so future inserts fall back to
    # the model's Python-side `default=90` instead of a DB-side default
    # (same reasoning as every other retention column here).
    op.alter_column("app_settings", "monitoring_history_retention_days", server_default=None)

    op.create_table(
        "machine_services",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("machine_id", sa.Uuid(), nullable=False),
        sa.Column("unit", sa.String(length=255), nullable=False),
        sa.Column("load_state", sa.String(length=32), nullable=False),
        sa.Column("active_state", sa.String(length=32), nullable=False),
        sa.Column("sub_state", sa.String(length=32), nullable=False),
        sa.Column("description", sa.String(length=500), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["machine_id"],
            ["machines.id"],
            name=op.f("fk_machine_services_machine_id_machines"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_machine_services")),
    )
    op.create_index(op.f("ix_machine_services_machine_id"), "machine_services", ["machine_id"])
    op.create_index(
        "ix_machine_services_machine_id_active_state",
        "machine_services",
        ["machine_id", "active_state"],
    )

    op.create_table(
        "machine_monitoring_samples",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("machine_id", sa.Uuid(), nullable=False),
        sa.Column("sampled_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("cpu_percent", sa.Float(), nullable=True),
        sa.Column("ram_used_bytes", sa.BigInteger(), nullable=True),
        sa.Column("ram_total_bytes", sa.BigInteger(), nullable=True),
        sa.Column("disks", sa.JSON(), nullable=True),
        sa.Column("failed_services_count", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(
            ["machine_id"],
            ["machines.id"],
            name=op.f("fk_machine_monitoring_samples_machine_id_machines"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_machine_monitoring_samples")),
    )
    op.create_index(
        op.f("ix_machine_monitoring_samples_machine_id"),
        "machine_monitoring_samples",
        ["machine_id"],
    )
    op.create_index(
        "ix_machine_monitoring_samples_machine_id_sampled_at",
        "machine_monitoring_samples",
        ["machine_id", "sampled_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_machine_monitoring_samples_machine_id_sampled_at",
        table_name="machine_monitoring_samples",
    )
    op.drop_index(
        op.f("ix_machine_monitoring_samples_machine_id"),
        table_name="machine_monitoring_samples",
    )
    op.drop_table("machine_monitoring_samples")

    op.drop_index(
        "ix_machine_services_machine_id_active_state", table_name="machine_services"
    )
    op.drop_index(op.f("ix_machine_services_machine_id"), table_name="machine_services")
    op.drop_table("machine_services")

    op.drop_column("app_settings", "monitoring_history_retention_days")

    op.drop_column("machines", "services_updated_at")
    op.drop_column("machines", "monitoring_updated_at")
    op.drop_column("machines", "monitoring_history_retention_days")
    op.drop_column("machines", "monitoring_interval_seconds")
    op.drop_column("machines", "os_id")
