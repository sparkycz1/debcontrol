"""add action.terminal permission

Revision ID: c1d2e3f4a5b6
Revises: b7c8d9e0f1a2
Create Date: 2026-08-30

"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c1d2e3f4a5b6"
down_revision: str | None = "b7c8d9e0f1a2"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    # Postgres requires this to not share a transaction with other DDL — see
    # wiki/Development.md's "Adding a new permission" — so it gets its own
    # standalone op.execute() call, and this migration does nothing else.
    op.execute("ALTER TYPE permission ADD VALUE 'action.terminal'")


def downgrade() -> None:
    # Postgres has no "ALTER TYPE ... DROP VALUE" — removing an enum label
    # requires rebuilding the type from scratch (rename, recreate, migrate
    # every column using it, drop the old one). Not worth it for a value
    # that, once added, no existing row can reference in a way that removing
    # a downstream permission use would ever have to reference again in a
    # downgrade meant only for immediate rollback of this one migration.
    # Left as a no-op, same as this codebase's other irreversible enum-value
    # additions would have to be, matching the "auth_method" RENAME VALUE
    # precedent's asymmetry between upgrade and downgrade cost.
    pass
