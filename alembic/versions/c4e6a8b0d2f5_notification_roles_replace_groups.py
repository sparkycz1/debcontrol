"""notification rules target roles, not a separate user-group concept

Revision ID: c4e6a8b0d2f5
Revises: b2d4f6a8c0e3
Create Date: 2026-09-12

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c4e6a8b0d2f5"
down_revision: str | None = "b2d4f6a8c0e3"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    # New join table: which roles a notification rule targets (recipients =
    # directly-listed users + every active user holding one of these roles).
    op.create_table(
        "notification_rule_roles",
        sa.Column("rule_id", sa.Uuid(), nullable=False),
        sa.Column("role_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["rule_id"], ["notification_rules.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["role_id"], ["roles.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("rule_id", "role_id"),
    )
    # `UserGroup` (a notification-only grouping concept, separate from
    # `Role`) is retired in favor of the new role targeting above — it never
    # had any use besides notification recipients, so there is no data
    # migration path: a rule that had a user-group recipient list needs its
    # role(s) picked again from the Notifications page after this upgrade.
    op.drop_table("notification_rule_user_groups")
    op.drop_table("user_group_members")
    op.drop_table("user_groups")


def downgrade() -> None:
    op.create_table(
        "user_groups",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(255), nullable=False, unique=True),
        sa.Column("description", sa.String(1024), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "user_group_members",
        sa.Column("user_group_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(["user_group_id"], ["user_groups.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("user_group_id", "user_id"),
    )
    op.create_table(
        "notification_rule_user_groups",
        sa.Column("rule_id", sa.Uuid(), nullable=False),
        sa.Column("user_group_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["rule_id"], ["notification_rules.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["user_group_id"], ["user_groups.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("rule_id", "user_group_id"),
    )
    op.drop_table("notification_rule_roles")
