"""add user.impersonate permission

Revision ID: b2d4f6a8c0e3
Revises: a1c3e5b7d9f2
Create Date: 2026-09-12

"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b2d4f6a8c0e3"
down_revision: str | None = "a1c3e5b7d9f2"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    # Its own migration, separate from the impersonator_id column above —
    # Postgres requires ADD VALUE to run outside any other DDL's transaction.
    # See wiki/Development's "Adding a new permission".
    op.execute("ALTER TYPE permission ADD VALUE 'user.impersonate'")


def downgrade() -> None:
    # Postgres has no "ALTER TYPE ... DROP VALUE" — see c1d2e3f4a5b6
    # (action.terminal) and e8f3b5c7d9a2 (ai.access) for the same asymmetry.
    pass
