"""Runbooks and their runs

Revision ID: a2c4e6f8b0d3
Revises: f1b3d5e7a9c2
Create Date: 2026-10-12

Two new tables; nothing existing changes.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a2c4e6f8b0d3"
down_revision: str | None = "f1b3d5e7a9c2"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.create_table(
        "runbooks",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("description", sa.String(length=1024), nullable=True),
        sa.Column("steps", sa.JSON(), nullable=False),
        sa.Column("params", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    status = postgresql.ENUM(
        "pending", "running", "succeeded", "failed", name="runbook_run_status", create_type=False
    )
    status.create(op.get_bind(), checkfirst=True)
    op.create_table(
        "runbook_runs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("runbook_id", sa.Uuid(), nullable=True),
        sa.Column("runbook_name", sa.String(length=120), nullable=False),
        sa.Column("machine_id", sa.Uuid(), nullable=False),
        sa.Column("batch_id", sa.Uuid(), nullable=False),
        sa.Column("status", status, nullable=False),
        sa.Column("commands", sa.JSON(), nullable=False),
        sa.Column("output", sa.Text(), nullable=True),
        sa.Column("error", sa.String(length=1024), nullable=True),
        sa.Column("started_by", sa.String(length=255), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["machine_id"], ["machines.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["runbook_id"], ["runbooks.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_runbook_runs_batch_id", "runbook_runs", ["batch_id"])
    op.create_index("ix_runbook_runs_machine_id", "runbook_runs", ["machine_id"])
    op.create_index("ix_runbook_runs_runbook_id", "runbook_runs", ["runbook_id"])


def downgrade() -> None:
    op.drop_table("runbook_runs")
    op.execute("DROP TYPE IF EXISTS runbook_run_status")
    op.drop_table("runbooks")
