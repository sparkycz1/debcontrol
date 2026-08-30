"""per-user machine group visibility scoping

Revision ID: f1a4c7d3b820
Revises: e8f3b5c7d9a2
Create Date: 2026-08-30

No backfill: a user with no rows in this table is unrestricted, so every
existing account keeps seeing exactly what it saw before. See
`app/db/models/user_machine_group_access.py`.

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f1a4c7d3b820"
down_revision: str | None = "e8f3b5c7d9a2"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.create_table(
        "user_machine_group_access",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("group_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_user_machine_group_access_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["group_id"],
            ["machine_groups.id"],
            name=op.f("fk_user_machine_group_access_group_id_machine_groups"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("user_id", "group_id", name=op.f("pk_user_machine_group_access")),
    )


def downgrade() -> None:
    op.drop_table("user_machine_group_access")
