"""scheduled task run history + per-user saved audit-log views

Revision ID: e5f7a9c1d3b6
Revises: d3f6a8c0b2e4
Create Date: 2026-09-08

"""

from __future__ import annotations

import uuid
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "e5f7a9c1d3b6"
down_revision: str | None = "d3f6a8c0b2e4"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.create_table(
        "scheduled_task_runs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scheduled_task_id", sa.Uuid(), nullable=False),
        sa.Column("action", sa.String(length=100), nullable=False),
        sa.Column(
            "status",
            sa.Enum("succeeded", "failed", name="scheduled_task_run_status"),
            nullable=False,
        ),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("attempted", sa.Integer(), nullable=False),
        sa.Column("skipped", sa.Integer(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["scheduled_task_id"],
            ["scheduled_tasks.id"],
            name=op.f("fk_scheduled_task_runs_scheduled_task_id_scheduled_tasks"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scheduled_task_runs")),
    )
    op.create_index(
        "ix_scheduled_task_runs_scheduled_task_id",
        "scheduled_task_runs",
        ["scheduled_task_id"],
    )

    op.create_table(
        "saved_audit_views",
        sa.Column("id", sa.Uuid(), primary_key=True, default=uuid.uuid4),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("query_string", sa.String(length=500), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_saved_audit_views_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("user_id", "name", name="uq_saved_audit_views_user_id_name"),
    )
    op.create_index("ix_saved_audit_views_user_id", "saved_audit_views", ["user_id"])


def downgrade() -> None:
    op.drop_index("ix_saved_audit_views_user_id", table_name="saved_audit_views")
    op.drop_table("saved_audit_views")

    op.drop_index(
        "ix_scheduled_task_runs_scheduled_task_id", table_name="scheduled_task_runs"
    )
    op.drop_table("scheduled_task_runs")
    sa.Enum(name="scheduled_task_run_status").drop(op.get_bind(), checkfirst=True)
