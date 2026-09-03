"""per-user saved machine-list views (saved_machine_views)

Revision ID: d6e8b3c1a7f9
Revises: c3d5f8a1b9e4
Create Date: 2026-09-04

"""

from __future__ import annotations

import uuid
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d6e8b3c1a7f9"
down_revision: str | None = "c3d5f8a1b9e4"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.create_table(
        "saved_machine_views",
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
            name=op.f("fk_saved_machine_views_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint(
            "user_id", "name", name="uq_saved_machine_views_user_id_name"
        ),
    )
    op.create_index(
        "ix_saved_machine_views_user_id", "saved_machine_views", ["user_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_saved_machine_views_user_id", table_name="saved_machine_views")
    op.drop_table("saved_machine_views")
