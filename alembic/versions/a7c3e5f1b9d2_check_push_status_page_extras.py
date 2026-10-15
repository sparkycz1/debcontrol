"""Push (heartbeat) checks and status page extras

Revision ID: a7c3e5f1b9d2
Revises: d7e1a3c5b9f2
Create Date: 2026-10-15

Two nullable columns on `endpoint_checks` (only push checks fill them), and
three status page settings; the two new status page options are off after
the upgrade, so an existing page looks exactly as it did.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a7c3e5f1b9d2"
down_revision: str | None = "d7e1a3c5b9f2"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column("endpoint_checks", sa.Column("push_token", sa.String(64), nullable=True))
    op.create_unique_constraint(
        op.f("uq_endpoint_checks_push_token"), "endpoint_checks", ["push_token"]
    )
    op.add_column(
        "endpoint_checks",
        sa.Column("last_push_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "app_settings",
        sa.Column(
            "status_page_show_latency", sa.Boolean(), server_default=sa.false(), nullable=False
        ),
    )
    op.add_column(
        "app_settings",
        sa.Column(
            "status_page_show_history", sa.Boolean(), server_default=sa.false(), nullable=False
        ),
    )
    op.add_column("app_settings", sa.Column("status_page_message", sa.String(500), nullable=True))


def downgrade() -> None:
    for name in ("status_page_message", "status_page_show_history", "status_page_show_latency"):
        op.drop_column("app_settings", name)
    op.drop_column("endpoint_checks", "last_push_at")
    op.drop_constraint(op.f("uq_endpoint_checks_push_token"), "endpoint_checks", type_="unique")
    op.drop_column("endpoint_checks", "push_token")
