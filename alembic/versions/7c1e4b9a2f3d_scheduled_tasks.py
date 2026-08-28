"""scheduled tasks

Revision ID: 7c1e4b9a2f3d
Revises: 3273688bdc8b
Create Date: 2026-08-28

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "7c1e4b9a2f3d"
down_revision: str | None = "3273688bdc8b"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.create_table(
        "scheduled_tasks",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("action", sa.String(length=100), nullable=False),
        sa.Column("action_params", sa.JSON(), nullable=True),
        sa.Column(
            "target_type",
            sa.Enum("machine", "group", "all_machines", name="schedule_target_type"),
            nullable=False,
        ),
        sa.Column("target_machine_id", sa.Uuid(), nullable=True),
        sa.Column("target_group_id", sa.Uuid(), nullable=True),
        sa.Column("cron_expression", sa.String(length=100), nullable=False),
        sa.Column("is_enabled", sa.Boolean(), nullable=False),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_run_summary", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["target_machine_id"],
            ["machines.id"],
            name=op.f("fk_scheduled_tasks_target_machine_id_machines"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["target_group_id"],
            ["machine_groups.id"],
            name=op.f("fk_scheduled_tasks_target_group_id_machine_groups"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scheduled_tasks")),
    )
    op.create_index(
        op.f("ix_scheduled_tasks_next_run_at"), "scheduled_tasks", ["next_run_at"]
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_scheduled_tasks_next_run_at"), table_name="scheduled_tasks")
    op.drop_table("scheduled_tasks")
    sa.Enum(name="schedule_target_type").drop(op.get_bind(), checkfirst=True)
