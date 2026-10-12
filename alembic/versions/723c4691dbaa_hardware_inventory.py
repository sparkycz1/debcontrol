"""Hardware inventory and warranty dates

Revision ID: 723c4691dbaa
Revises: b3d5f7a9c1e4
Create Date: 2026-10-12

Nullable columns only. Vendor, model and serial fill in at each machine's
next facts refresh.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "723c4691dbaa"
down_revision: str | None = "b3d5f7a9c1e4"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None

_COLUMNS = (
    ("hw_vendor", sa.String(length=128)),
    ("hw_model", sa.String(length=128)),
    ("hw_serial", sa.String(length=128)),
    ("asset_serial", sa.String(length=128)),
    ("purchase_date", sa.Date()),
    ("warranty_until", sa.Date()),
    ("asset_note", sa.String(length=255)),
)


def upgrade() -> None:
    for name, column_type in _COLUMNS:
        op.add_column("machines", sa.Column(name, column_type, nullable=True))


def downgrade() -> None:
    for name, _column_type in reversed(_COLUMNS):
        op.drop_column("machines", name)
