"""AI summary of the cause on a notification rule

Revision ID: c8e0a2b4d6f9
Revises: b7d9f1a3c5e8
Create Date: 2026-10-12

One column, false for every existing rule: nothing is sent to an AI
provider until a rule is changed to ask for it.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c8e0a2b4d6f9"
down_revision: str | None = "b7d9f1a3c5e8"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column(
        "notification_rules",
        sa.Column("ai_summary", sa.Boolean(), server_default=sa.false(), nullable=False),
    )


def downgrade() -> None:
    op.drop_column("notification_rules", "ai_summary")
