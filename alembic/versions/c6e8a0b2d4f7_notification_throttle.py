"""Notification rules: a throttle window, and what each delivery was about

Revision ID: c6e8a0b2d4f7
Revises: b5d7f9a1c3e6
Create Date: 2026-10-04

`notification_rules.throttle_minutes` (NULL = send every notification, as
before) and `notification_logs.source_key` (the machine or endpoint check
a delivery was about, so a rule's throttle window is per source). Both
nullable: existing rules and history rows need no backfill.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c6e8a0b2d4f7"
down_revision: str | None = "b5d7f9a1c3e6"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column(
        "notification_rules", sa.Column("throttle_minutes", sa.Integer(), nullable=True)
    )
    op.add_column(
        "notification_logs", sa.Column("source_key", sa.String(length=300), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("notification_logs", "source_key")
    op.drop_column("notification_rules", "throttle_minutes")
