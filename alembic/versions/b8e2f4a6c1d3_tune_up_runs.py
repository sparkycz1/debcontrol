"""Tune-up ("Komplet"): every maintenance step for a machine in one go

A new table, `tune_up_runs`: one row per machine of a tune-up, with the
steps it runs and how each went. Nothing existing changes.

Revision ID: b8e2f4a6c1d3
Revises: a3d7e1f5c9b2
Create Date: 2026-11-23 20:30:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "b8e2f4a6c1d3"
down_revision: str | None = "a3d7e1f5c9b2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "tune_up_runs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("batch_id", sa.Uuid(), nullable=False),
        sa.Column("machine_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("options", sa.JSON(), nullable=False),
        sa.Column("steps", sa.JSON(), nullable=False),
        sa.Column("error", sa.String(length=1024), nullable=True),
        sa.Column("hold_order", sa.Integer(), nullable=True),
        sa.Column("started_by", sa.String(length=255), nullable=True),
        sa.Column("cancel_requested_by", sa.String(length=255), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("queued_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["machine_id"], ["machines.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_tune_up_runs_batch_id", "tune_up_runs", ["batch_id"])
    op.create_index("ix_tune_up_runs_machine_id", "tune_up_runs", ["machine_id"])
    op.create_index(
        "ix_tune_up_runs_open",
        "tune_up_runs",
        ["status"],
        postgresql_where=sa.text("status IN ('pending', 'running')"),
    )


def downgrade() -> None:
    op.drop_index("ix_tune_up_runs_open", table_name="tune_up_runs")
    op.drop_index("ix_tune_up_runs_machine_id", table_name="tune_up_runs")
    op.drop_index("ix_tune_up_runs_batch_id", table_name="tune_up_runs")
    op.drop_table("tune_up_runs")
