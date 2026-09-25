"""maintenance_windows (mute machine notifications for a time range)

Revision ID: a7b9c1d3e5f8
Revises: f6a8b0c2d4e7
Create Date: 2026-09-25

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a7b9c1d3e5f8"
down_revision: str | None = "f6a8b0c2d4e7"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    # New tables only — nothing is muted until someone schedules a window.
    op.create_table(
        "maintenance_windows",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("starts_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ends_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("all_machines", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_maintenance_windows")),
    )
    op.create_index("ix_maintenance_windows_ends_at", "maintenance_windows", ["ends_at"])
    op.create_table(
        "maintenance_window_machine_groups",
        sa.Column("window_id", sa.Uuid(), nullable=False),
        sa.Column("machine_group_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["machine_group_id"],
            ["machine_groups.id"],
            name=op.f("fk_maintenance_window_machine_groups_machine_group_id_machine_groups"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["window_id"],
            ["maintenance_windows.id"],
            name=op.f("fk_maintenance_window_machine_groups_window_id_maintenance_windows"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "window_id", "machine_group_id", name=op.f("pk_maintenance_window_machine_groups")
        ),
    )
    op.create_table(
        "maintenance_window_machines",
        sa.Column("window_id", sa.Uuid(), nullable=False),
        sa.Column("machine_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["machine_id"],
            ["machines.id"],
            name=op.f("fk_maintenance_window_machines_machine_id_machines"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["window_id"],
            ["maintenance_windows.id"],
            name=op.f("fk_maintenance_window_machines_window_id_maintenance_windows"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "window_id", "machine_id", name=op.f("pk_maintenance_window_machines")
        ),
    )


def downgrade() -> None:
    op.drop_table("maintenance_window_machines")
    op.drop_table("maintenance_window_machine_groups")
    op.drop_index("ix_maintenance_windows_ends_at", table_name="maintenance_windows")
    op.drop_table("maintenance_windows")
