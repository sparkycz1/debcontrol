"""add notification.view permission

Revision ID: d8e0f2a4b6c8
Revises: c7d9e1f3a5b7
Create Date: 2026-09-11

"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d8e0f2a4b6c8"
down_revision: str | None = "c7d9e1f3a5b7"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    # Postgres requires this to not share a transaction with other DDL — see
    # wiki/Development's "Adding a new permission" — so it gets its own
    # standalone op.execute() call, and this migration does nothing else.
    op.execute("ALTER TYPE permission ADD VALUE 'notification.view'")


def downgrade() -> None:
    # Postgres has no "ALTER TYPE ... DROP VALUE" — see c1d2e3f4a5b6
    # (action.terminal) and e8f3b5c7d9a2 (ai.access) for the same asymmetry.
    pass
