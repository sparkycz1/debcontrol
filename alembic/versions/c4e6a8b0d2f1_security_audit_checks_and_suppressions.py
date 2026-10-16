"""Security audit: debcontrol's own checks, Lynis details, findings marked OK

Revision ID: c4e6a8b0d2f1
Revises: b8d1f3a5c7e9
Create Date: 2026-10-16

Three nullable JSON columns on `security_audits` (older audits simply have
none) and a new table; nothing existing changes.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c4e6a8b0d2f1"
down_revision: str | None = "b8d1f3a5c7e9"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column("security_audits", sa.Column("checks", sa.JSON(), nullable=True))
    op.add_column("security_audits", sa.Column("details", sa.JSON(), nullable=True))
    op.add_column("security_audits", sa.Column("facts", sa.JSON(), nullable=True))
    op.create_table(
        "security_audit_suppressions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("machine_id", sa.Uuid(), nullable=False),
        sa.Column("key", sa.String(length=128), nullable=False),
        sa.Column("label", sa.String(length=500), nullable=False),
        sa.Column("note", sa.String(length=500), nullable=True),
        sa.Column("created_by", sa.String(length=255), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["machine_id"], ["machines.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("machine_id", "key", name="uq_security_audit_suppressions_machine_key"),
    )


def downgrade() -> None:
    op.drop_table("security_audit_suppressions")
    op.drop_column("security_audits", "facts")
    op.drop_column("security_audits", "details")
    op.drop_column("security_audits", "checks")
