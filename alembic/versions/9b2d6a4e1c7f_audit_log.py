"""audit log

Revision ID: 9b2d6a4e1c7f
Revises: 7c1e4b9a2f3d
Create Date: 2026-08-29

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "9b2d6a4e1c7f"
down_revision: str | None = "7c1e4b9a2f3d"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.create_table(
        "audit_log_entries",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("actor", sa.String(length=255), nullable=True),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("action", sa.String(length=100), nullable=False),
        sa.Column(
            "outcome",
            sa.Enum("success", "denied", "failure", name="audit_outcome"),
            nullable=False,
        ),
        sa.Column("target_type", sa.String(length=50), nullable=True),
        sa.Column("target_id", sa.String(length=64), nullable=True),
        sa.Column("target_label", sa.String(length=255), nullable=True),
        sa.Column("summary", sa.String(length=500), nullable=False),
        sa.Column("details", sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_log_entries")),
    )
    op.create_index(
        op.f("ix_audit_log_entries_created_at"), "audit_log_entries", ["created_at"]
    )
    op.create_index(op.f("ix_audit_log_entries_action"), "audit_log_entries", ["action"])


def downgrade() -> None:
    op.drop_index(op.f("ix_audit_log_entries_action"), table_name="audit_log_entries")
    op.drop_index(op.f("ix_audit_log_entries_created_at"), table_name="audit_log_entries")
    op.drop_table("audit_log_entries")
    sa.Enum(name="audit_outcome").drop(op.get_bind(), checkfirst=True)
