"""add ai.access permission

Revision ID: e8f3b5c7d9a2
Revises: d7e2a4b6c8f1
Create Date: 2026-08-30

"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "e8f3b5c7d9a2"
down_revision: str | None = "d7e2a4b6c8f1"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    # Postgres requires this to not share a transaction with other DDL — see
    # wiki/Development's "Adding a new permission" — so it gets its own
    # standalone op.execute() call, and this migration does nothing else
    # (the AI feature's tables live in d7e2a4b6c8f1, the revision before
    # this one, for exactly that reason).
    op.execute("ALTER TYPE permission ADD VALUE 'ai.access'")


def downgrade() -> None:
    # Same as c1d2e3f4a5b6 (action.terminal): Postgres has no
    # "ALTER TYPE ... DROP VALUE", and rebuilding the whole enum type to
    # remove one label isn't worth it for a rollback of a single migration.
    pass
