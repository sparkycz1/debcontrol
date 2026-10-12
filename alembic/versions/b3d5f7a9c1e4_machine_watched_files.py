"""Files watched for changes on a machine

Revision ID: b3d5f7a9c1e4
Revises: a2c4e6f8b0d3
Create Date: 2026-10-12

One new table; nothing is watched until someone lists a file.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b3d5f7a9c1e4"
down_revision: str | None = "a2c4e6f8b0d3"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.create_table(
        "machine_watched_files",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("machine_id", sa.Uuid(), nullable=False),
        sa.Column("path", sa.String(length=512), nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=True),
        sa.Column("content_encrypted", sa.LargeBinary(), nullable=True),
        sa.Column("previous_content_encrypted", sa.LargeBinary(), nullable=True),
        sa.Column("lines_added", sa.Integer(), nullable=True),
        sa.Column("lines_removed", sa.Integer(), nullable=True),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("changed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["machine_id"], ["machines.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("machine_id", "path", name="uq_machine_watched_files_path"),
    )
    op.create_index(
        "ix_machine_watched_files_machine_id", "machine_watched_files", ["machine_id"]
    )


def downgrade() -> None:
    op.drop_table("machine_watched_files")
