"""Machine health: stored findings and status, per-problem snoozes,
fleet health score, health thresholds

Revision ID: b3d8f1a6c2e9
Revises: 9a4c7e2b5d1f
Create Date: 2026-11-22 14:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "b3d8f1a6c2e9"
down_revision: str | None = "9a4c7e2b5d1f"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_THRESHOLDS = (
    ("health_cpu_warn_percent", "85"),
    ("health_cpu_critical_percent", "95"),
    ("health_memory_warn_percent", "85"),
    ("health_memory_critical_percent", "95"),
    ("health_disk_warn_percent", "85"),
    ("health_disk_critical_percent", "95"),
    ("health_temperature_warn_celsius", "80"),
    ("health_temperature_critical_celsius", "90"),
    ("health_disk_full_warn_days", "7"),
    ("health_disk_full_critical_days", "2"),
)


def upgrade() -> None:
    op.create_table(
        "machine_health_snoozes",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("machine_id", sa.Uuid(), nullable=False),
        sa.Column("finding_key", sa.String(length=255), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("note", sa.String(length=500), nullable=True),
        sa.Column("created_by", sa.String(length=255), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["machine_id"], ["machines.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("machine_id", "finding_key"),
    )
    op.create_index(
        op.f("ix_machine_health_snoozes_machine_id"), "machine_health_snoozes", ["machine_id"]
    )
    # NULL = not evaluated yet: the first evaluation after the upgrade
    # fills it in (and sends no "health got worse" notification).
    op.add_column("machines", sa.Column("health", sa.JSON(), nullable=True))
    op.add_column("machines", sa.Column("health_status", sa.String(length=16), nullable=True))
    op.create_index(op.f("ix_machines_health_status"), "machines", ["health_status"])
    op.add_column("fleet_snapshots", sa.Column("health_score", sa.Integer(), nullable=True))
    for name, default in _THRESHOLDS:
        op.add_column(
            "app_settings",
            sa.Column(name, sa.Integer(), nullable=False, server_default=default),
        )


def downgrade() -> None:
    for name, _default in reversed(_THRESHOLDS):
        op.drop_column("app_settings", name)
    op.drop_column("fleet_snapshots", "health_score")
    op.drop_index(op.f("ix_machines_health_status"), table_name="machines")
    op.drop_column("machines", "health_status")
    op.drop_column("machines", "health")
    op.drop_index(
        op.f("ix_machine_health_snoozes_machine_id"), table_name="machine_health_snoozes"
    )
    op.drop_table("machine_health_snoozes")
