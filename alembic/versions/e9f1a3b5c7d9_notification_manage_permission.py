"""add notification.manage permission

Revision ID: e9f1a3b5c7d9
Revises: d8e0f2a4b6c8
Create Date: 2026-09-11

"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "e9f1a3b5c7d9"
down_revision: str | None = "d8e0f2a4b6c8"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    # Same reasoning (and same requirement to be its own migration, separate
    # from notification.view's) as d8e0f2a4b6c8 — see wiki/Development's
    # "Adding a new permission".
    op.execute("ALTER TYPE permission ADD VALUE 'notification.manage'")


def downgrade() -> None:
    # Postgres has no "ALTER TYPE ... DROP VALUE" — see c1d2e3f4a5b6
    # (action.terminal) and e8f3b5c7d9a2 (ai.access) for the same asymmetry.
    pass
