"""Named, reusable notification email templates a rule can opt into

Revision ID: f2a6c9d1e4b8
Revises: e1c4a7f0b3d6
Create Date: 2026-09-12

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f2a6c9d1e4b8"
down_revision: str | None = "e1c4a7f0b3d6"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.create_table(
        "notification_custom_templates",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
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
        sa.PrimaryKeyConstraint("id", name=op.f("pk_notification_custom_templates")),
        sa.UniqueConstraint("name", name=op.f("uq_notification_custom_templates_name")),
    )

    op.add_column(
        "notification_rules",
        sa.Column("custom_template_id", sa.Uuid(), nullable=True),
    )
    op.create_foreign_key(
        op.f("fk_notification_rules_custom_template_id_notification_custom_templates"),
        "notification_rules",
        "notification_custom_templates",
        ["custom_template_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint(
        op.f("fk_notification_rules_custom_template_id_notification_custom_templates"),
        "notification_rules",
        type_="foreignkey",
    )
    op.drop_column("notification_rules", "custom_template_id")
    op.drop_table("notification_custom_templates")
