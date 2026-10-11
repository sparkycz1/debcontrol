"""Endpoint checks can run from a managed machine

Revision ID: d3f5b7c9e1a4
Revises: c2e4a6b8d0f3
Create Date: 2026-10-11

One nullable column: NULL keeps a check running from the debcontrol
server, exactly as before.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d3f5b7c9e1a4"
down_revision: str | None = "c2e4a6b8d0f3"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    with op.batch_alter_table("endpoint_checks") as batch:
        batch.add_column(sa.Column("source_machine_id", sa.Uuid(), nullable=True))
        batch.create_foreign_key(
            "fk_endpoint_checks_source_machine_id_machines",
            "machines",
            ["source_machine_id"],
            ["id"],
            ondelete="CASCADE",
        )
        batch.create_index(
            "ix_endpoint_checks_source_machine_id", ["source_machine_id"], unique=False
        )


def downgrade() -> None:
    with op.batch_alter_table("endpoint_checks") as batch:
        batch.drop_index("ix_endpoint_checks_source_machine_id")
        batch.drop_constraint("fk_endpoint_checks_source_machine_id_machines", type_="foreignkey")
        batch.drop_column("source_machine_id")
