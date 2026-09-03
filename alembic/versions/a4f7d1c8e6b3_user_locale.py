"""per-user UI language (locale)

Revision ID: a4f7d1c8e6b3
Revises: b3d8e6f4a1c9
Create Date: 2026-09-03

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a4f7d1c8e6b3"
down_revision: str | None = "b3d8e6f4a1c9"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    # Nullable, no server default: NULL means "use the default locale"
    # (English) — see app/i18n/__init__.py and User.locale's own docstring.
    # Every existing account on an upgraded instance reads as NULL here,
    # which is exactly the same "no preference set yet" state a brand-new
    # account starts in, so this needs no backfill.
    op.add_column("users", sa.Column("locale", sa.String(length=16), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "locale")
