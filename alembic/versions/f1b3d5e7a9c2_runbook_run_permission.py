"""add runbook.run permission

Revision ID: f1b3d5e7a9c2
Revises: e0a2c4d6f8b1
Create Date: 2026-10-12

Its own migration, like every permission before it: see
wiki/Development's "Adding a new permission".
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f1b3d5e7a9c2"
down_revision: str | None = "e0a2c4d6f8b1"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.execute("ALTER TYPE permission ADD VALUE 'runbook.run'")


def downgrade() -> None:
    # Postgres has no "ALTER TYPE ... DROP VALUE".
    pass
