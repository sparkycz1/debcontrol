"""Index on notification_logs.rule_id

Revision ID: b8e4c1d9f6a2
Revises: a3c7f5e8b2d1
Create Date: 2026-09-13

Supports the new `?rule_id=` filter on GET /notifications/history (a link
from each rule's own edit page to "view delivery history for this rule")
without a full-table scan as delivery history accumulates.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b8e4c1d9f6a2"
down_revision: str | None = "a3c7f5e8b2d1"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.create_index(
        op.f("ix_notification_logs_rule_id"),
        "notification_logs",
        ["rule_id"],
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_notification_logs_rule_id"), table_name="notification_logs")
