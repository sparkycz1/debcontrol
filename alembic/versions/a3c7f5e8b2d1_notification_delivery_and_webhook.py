"""Notification webhook delivery channel and delivery history log

Revision ID: a3c7f5e8b2d1
Revises: f2a6c9d1e4b8
Create Date: 2026-09-13

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a3c7f5e8b2d1"
down_revision: str | None = "f2a6c9d1e4b8"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column(
        "notification_rules",
        sa.Column("delivery_channel", sa.String(length=16), server_default="email", nullable=False),
    )
    op.add_column(
        "notification_rules",
        sa.Column("webhook_url", sa.String(length=2048), nullable=True),
    )
    op.add_column(
        "app_settings",
        sa.Column(
            "notification_log_retention_days", sa.Integer(), server_default="90", nullable=True
        ),
    )

    op.create_table(
        "notification_logs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("rule_id", sa.Uuid(), nullable=True),
        sa.Column("rule_name", sa.String(length=255), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("channel", sa.String(length=16), nullable=False),
        sa.Column("target", sa.String(length=2048), nullable=False),
        sa.Column("machine_name", sa.String(length=255), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("error", sa.String(length=2000), nullable=True),
        sa.Column("is_test", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column(
            "sent_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["rule_id"],
            ["notification_rules.id"],
            name=op.f("fk_notification_logs_rule_id_notification_rules"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_notification_logs")),
    )
    op.create_index(
        op.f("ix_notification_logs_sent_at"),
        "notification_logs",
        ["sent_at"],
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_notification_logs_sent_at"), table_name="notification_logs")
    op.drop_table("notification_logs")
    op.drop_column("app_settings", "notification_log_retention_days")
    op.drop_column("notification_rules", "webhook_url")
    op.drop_column("notification_rules", "delivery_channel")
