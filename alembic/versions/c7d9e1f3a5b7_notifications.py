"""Notifications: user email, user groups, notification rules and templates

Revision ID: c7d9e1f3a5b7
Revises: b6c7d8e9f0a1
Create Date: 2026-09-11

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c7d9e1f3a5b7"
down_revision: str | None = "b6c7d8e9f0a1"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    # --- users.email ------------------------------------------------------
    op.add_column("users", sa.Column("email", sa.String(length=255), nullable=True))
    op.create_unique_constraint(op.f("uq_users_email"), "users", ["email"])

    # --- user_groups + membership ------------------------------------------
    op.create_table(
        "user_groups",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.String(length=1024), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_user_groups")),
        sa.UniqueConstraint("name", name=op.f("uq_user_groups_name")),
    )
    op.create_table(
        "user_group_members",
        sa.Column("user_group_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_group_id"],
            ["user_groups.id"],
            name=op.f("fk_user_group_members_user_group_id_user_groups"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_user_group_members_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("user_group_id", "user_id", name=op.f("pk_user_group_members")),
    )

    # --- notification_rules -------------------------------------------------
    op.create_table(
        "notification_rules",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.String(length=1024), nullable=True),
        sa.Column("enabled", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("event_types", sa.JSON(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_notification_rules")),
        sa.UniqueConstraint("name", name=op.f("uq_notification_rules_name")),
    )
    op.create_table(
        "notification_rule_users",
        sa.Column("rule_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["rule_id"],
            ["notification_rules.id"],
            name=op.f("fk_notification_rule_users_rule_id_notification_rules"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_notification_rule_users_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("rule_id", "user_id", name=op.f("pk_notification_rule_users")),
    )
    op.create_table(
        "notification_rule_user_groups",
        sa.Column("rule_id", sa.Uuid(), nullable=False),
        sa.Column("user_group_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["rule_id"],
            ["notification_rules.id"],
            name=op.f("fk_notification_rule_user_groups_rule_id_notification_rules"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_group_id"],
            ["user_groups.id"],
            name=op.f("fk_notification_rule_user_groups_user_group_id_user_groups"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "rule_id", "user_group_id", name=op.f("pk_notification_rule_user_groups")
        ),
    )
    op.create_table(
        "notification_rule_machines",
        sa.Column("rule_id", sa.Uuid(), nullable=False),
        sa.Column("machine_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["rule_id"],
            ["notification_rules.id"],
            name=op.f("fk_notification_rule_machines_rule_id_notification_rules"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["machine_id"],
            ["machines.id"],
            name=op.f("fk_notification_rule_machines_machine_id_machines"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "rule_id", "machine_id", name=op.f("pk_notification_rule_machines")
        ),
    )
    op.create_table(
        "notification_rule_machine_groups",
        sa.Column("rule_id", sa.Uuid(), nullable=False),
        sa.Column("machine_group_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["rule_id"],
            ["notification_rules.id"],
            name=op.f("fk_notification_rule_machine_groups_rule_id_notification_rules"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["machine_group_id"],
            ["machine_groups.id"],
            name=op.f(
                "fk_notification_rule_machine_groups_machine_group_id_machine_groups"
            ),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "rule_id", "machine_group_id", name=op.f("pk_notification_rule_machine_groups")
        ),
    )

    # --- notification_templates ---------------------------------------------
    op.create_table(
        "notification_templates",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("subject", sa.String(length=500), nullable=False),
        sa.Column("body", sa.String(length=4000), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_notification_templates")),
        sa.UniqueConstraint("event_type", name=op.f("uq_notification_templates_event_type")),
    )


def downgrade() -> None:
    op.drop_table("notification_templates")
    op.drop_table("notification_rule_machine_groups")
    op.drop_table("notification_rule_machines")
    op.drop_table("notification_rule_user_groups")
    op.drop_table("notification_rule_users")
    op.drop_table("notification_rules")
    op.drop_table("user_group_members")
    op.drop_table("user_groups")
    op.drop_constraint(op.f("uq_users_email"), "users", type_="unique")
    op.drop_column("users", "email")
