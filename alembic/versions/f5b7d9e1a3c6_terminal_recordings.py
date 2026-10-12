"""Terminal session recordings

Revision ID: f5b7d9e1a3c6
Revises: e4a6c8d0f2b5
Create Date: 2026-10-11

A new table and two settings. Recording is off after the upgrade.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f5b7d9e1a3c6"
down_revision: str | None = "e4a6c8d0f2b5"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column(
        "app_settings",
        sa.Column(
            "terminal_recording_enabled", sa.Boolean(), server_default=sa.false(), nullable=False
        ),
    )
    op.add_column(
        "app_settings",
        sa.Column(
            "terminal_recording_retention_days", sa.Integer(), server_default="30", nullable=True
        ),
    )
    op.create_table(
        "terminal_recordings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("machine_id", sa.Uuid(), nullable=True),
        sa.Column("machine_name", sa.String(length=255), nullable=False),
        sa.Column("username", sa.String(length=255), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=False),
        sa.Column("duration_seconds", sa.Float(), nullable=False),
        sa.Column("cols", sa.Integer(), nullable=False),
        sa.Column("rows", sa.Integer(), nullable=False),
        sa.Column("output_bytes", sa.Integer(), nullable=False),
        sa.Column("truncated", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("data_encrypted", sa.LargeBinary(), nullable=False),
        sa.ForeignKeyConstraint(["machine_id"], ["machines.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_terminal_recordings_started_at", "terminal_recordings", ["started_at"])
    op.create_index(
        "ix_terminal_recordings_machine_id_started_at",
        "terminal_recordings",
        ["machine_id", "started_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_terminal_recordings_machine_id_started_at", table_name="terminal_recordings")
    op.drop_index("ix_terminal_recordings_started_at", table_name="terminal_recordings")
    op.drop_table("terminal_recordings")
    op.drop_column("app_settings", "terminal_recording_retention_days")
    op.drop_column("app_settings", "terminal_recording_enabled")
