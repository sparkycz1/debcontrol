"""Condition-based notification rules (CPU/RAM/disk/facts thresholds) and
the app-wide check interval for evaluating them

Revision ID: e1c4a7f0b3d6
Revises: d5f7b9c1e3a6
Create Date: 2026-09-12

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "e1c4a7f0b3d6"
down_revision: str | None = "d5f7b9c1e3a6"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column(
        "app_settings",
        sa.Column(
            "notification_condition_check_interval_seconds",
            sa.Integer(),
            server_default="60",
            nullable=False,
        ),
    )

    op.create_table(
        "notification_conditions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("rule_id", sa.Uuid(), nullable=False),
        sa.Column("field", sa.String(length=64), nullable=False),
        sa.Column("operator", sa.String(length=16), nullable=False),
        sa.Column("value", sa.String(length=255), nullable=False),
        sa.Column("mount_point", sa.String(length=255), nullable=True),
        sa.Column("sustained_seconds", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(
            ["rule_id"],
            ["notification_rules.id"],
            name=op.f("fk_notification_conditions_rule_id_notification_rules"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_notification_conditions")),
    )
    op.create_index(
        op.f("ix_notification_conditions_rule_id"),
        "notification_conditions",
        ["rule_id"],
    )

    op.create_table(
        "notification_condition_state",
        sa.Column("rule_id", sa.Uuid(), nullable=False),
        sa.Column("machine_id", sa.Uuid(), nullable=False),
        sa.Column("matched", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("first_matched_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("notified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["rule_id"],
            ["notification_rules.id"],
            name=op.f("fk_notification_condition_state_rule_id_notification_rules"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["machine_id"],
            ["machines.id"],
            name=op.f("fk_notification_condition_state_machine_id_machines"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "rule_id", "machine_id", name=op.f("pk_notification_condition_state")
        ),
    )


def downgrade() -> None:
    op.drop_table("notification_condition_state")
    op.drop_index(
        op.f("ix_notification_conditions_rule_id"), table_name="notification_conditions"
    )
    op.drop_table("notification_conditions")
    op.drop_column("app_settings", "notification_condition_check_interval_seconds")
