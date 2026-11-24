"""Usual behavior of each machine (anomaly detection)

A new `machine_baselines` table (one row per machine, filled by the nightly
job) and three settings on `app_settings`, all with server defaults.
Nothing existing changes; a machine is compared with its usual behavior
only once two weeks of its history have been learned.

Revision ID: f2b6d8a4c1e7
Revises: d5a1c7e3b9f2
Create Date: 2026-11-24 20:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "f2b6d8a4c1e7"
down_revision: str | None = "d5a1c7e3b9f2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "machine_baselines",
        sa.Column("machine_id", sa.Uuid(), nullable=False),
        sa.Column("computed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("since", sa.DateTime(timezone=True), nullable=True),
        sa.Column("sample_count", sa.Integer(), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(["machine_id"], ["machines.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("machine_id"),
    )
    with op.batch_alter_table("app_settings") as batch:
        batch.add_column(
            sa.Column(
                "health_anomaly_detection",
                sa.Boolean(),
                server_default=sa.text("true"),
                nullable=False,
            )
        )
        batch.add_column(
            sa.Column(
                "health_anomaly_deviations", sa.Integer(), server_default="4", nullable=False
            )
        )
        batch.add_column(
            sa.Column(
                "health_anomaly_mute_usual",
                sa.Boolean(),
                server_default=sa.text("true"),
                nullable=False,
            )
        )


def downgrade() -> None:
    with op.batch_alter_table("app_settings") as batch:
        batch.drop_column("health_anomaly_mute_usual")
        batch.drop_column("health_anomaly_deviations")
        batch.drop_column("health_anomaly_detection")
    op.drop_table("machine_baselines")
