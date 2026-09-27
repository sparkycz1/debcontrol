"""upgrade strategies: safe "upgrade" and "security" (security updates only)

Revision ID: e2f4a6b8c0d1
Revises: d1e3f5a7b9c2
Create Date: 2026-09-27

"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "e2f4a6b8c0d1"
down_revision: str | None = "d1e3f5a7b9c2"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    # Enum labels only — nothing else in this migration (see
    # wiki/Development.md's "Adding a new permission" for why Postgres wants
    # ALTER TYPE ... ADD VALUE on its own).
    op.execute("ALTER TYPE upgrade_strategy ADD VALUE IF NOT EXISTS 'upgrade'")
    op.execute("ALTER TYPE upgrade_strategy ADD VALUE IF NOT EXISTS 'security'")


def downgrade() -> None:
    # Postgres has no "ALTER TYPE ... DROP VALUE"; the extra labels are
    # harmless to an older version that never writes them.
    pass
