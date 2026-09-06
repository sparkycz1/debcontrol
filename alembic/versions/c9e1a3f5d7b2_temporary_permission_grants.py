"""temporary_permission_grants table

Revision ID: c9e1a3f5d7b2
Revises: b7d3f5a9c1e6
Create Date: 2026-09-06

"""

from __future__ import annotations

import uuid
from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c9e1a3f5d7b2"
down_revision: str | None = "b7d3f5a9c1e6"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.create_table(
        "temporary_permission_grants",
        sa.Column("id", sa.Uuid(), primary_key=True, default=uuid.uuid4),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column(
            "permission",
            postgresql.ENUM(name="permission", create_type=False),
            nullable=False,
        ),
        sa.Column("granted_by_id", sa.Uuid(), nullable=True),
        sa.Column("granted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_temporary_permission_grants_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["granted_by_id"],
            ["users.id"],
            name=op.f("fk_temporary_permission_grants_granted_by_id_users"),
            ondelete="SET NULL",
        ),
    )
    op.create_index(
        "ix_temporary_permission_grants_user_id",
        "temporary_permission_grants",
        ["user_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_temporary_permission_grants_user_id", table_name="temporary_permission_grants"
    )
    op.drop_table("temporary_permission_grants")
