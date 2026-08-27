"""machine groups

Revision ID: f72dca97d347
Revises: a223c4d67523
Create Date: 2026-08-27

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f72dca97d347"
down_revision: str | None = "a223c4d67523"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.create_table(
        "machine_groups",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.String(length=1024), nullable=True),
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
        sa.PrimaryKeyConstraint("id", name=op.f("pk_machine_groups")),
        sa.UniqueConstraint("name", name=op.f("uq_machine_groups_name")),
    )

    op.add_column("machines", sa.Column("group_id", sa.Uuid(), nullable=True))
    op.create_index(op.f("ix_machines_group_id"), "machines", ["group_id"])
    op.create_foreign_key(
        op.f("fk_machines_group_id_machine_groups"),
        "machines",
        "machine_groups",
        ["group_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint(op.f("fk_machines_group_id_machine_groups"), "machines", type_="foreignkey")
    op.drop_index(op.f("ix_machines_group_id"), table_name="machines")
    op.drop_column("machines", "group_id")
    op.drop_table("machine_groups")
