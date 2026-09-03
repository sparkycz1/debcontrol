"""machine runbook (machines.runbook)

Revision ID: e2f4a6c8b0d3
Revises: d6e8b3c1a7f9
Create Date: 2026-09-04

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "e2f4a6c8b0d3"
down_revision: str | None = "d6e8b3c1a7f9"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column("machines", sa.Column("runbook", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("machines", "runbook")
