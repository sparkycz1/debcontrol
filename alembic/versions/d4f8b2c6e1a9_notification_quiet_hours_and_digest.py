"""Notification rules: quiet hours and a daily summary, and the held
notifications waiting for it

Revision ID: d4f8b2c6e1a9
Revises: c7e2a9f4d1b3
Create Date: 2026-11-22 17:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "d4f8b2c6e1a9"
down_revision: str | None = "c7e2a9f4d1b3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # All nullable or with a server default: existing rules keep sending
    # every notification at once, as before.
    op.add_column(
        "notification_rules", sa.Column("quiet_hours_start", sa.String(length=5), nullable=True)
    )
    op.add_column(
        "notification_rules", sa.Column("quiet_hours_end", sa.String(length=5), nullable=True)
    )
    op.add_column(
        "notification_rules",
        sa.Column(
            "quiet_hours_urgent", sa.Boolean(), server_default=sa.true(), nullable=False
        ),
    )
    op.add_column(
        "notification_rules", sa.Column("digest_time", sa.String(length=5), nullable=True)
    )
    op.add_column(
        "notification_rules",
        sa.Column(
            "digest_fleet_status", sa.Boolean(), server_default=sa.false(), nullable=False
        ),
    )
    op.add_column(
        "notification_rules", sa.Column("digest_last_sent_at", sa.DateTime(), nullable=True)
    )
    op.create_table(
        "notification_held_items",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("rule_id", sa.Uuid(), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("machine_name", sa.String(length=255), nullable=True),
        sa.Column("context", sa.JSON(), nullable=False),
        sa.Column("reason", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["rule_id"], ["notification_rules.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_notification_held_items_rule_id", "notification_held_items", ["rule_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_notification_held_items_rule_id", table_name="notification_held_items")
    op.drop_table("notification_held_items")
    for column in (
        "digest_last_sent_at",
        "digest_fleet_status",
        "digest_time",
        "quiet_hours_urgent",
        "quiet_hours_end",
        "quiet_hours_start",
    ):
        op.drop_column("notification_rules", column)
