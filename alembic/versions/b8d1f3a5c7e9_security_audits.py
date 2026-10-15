"""Lynis security audits

Revision ID: b8d1f3a5c7e9
Revises: c9f25da0b706
Create Date: 2026-10-15

A new table only; nothing existing changes.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b8d1f3a5c7e9"
down_revision: str | None = "c9f25da0b706"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    status = postgresql.ENUM(
        "pending", "running", "succeeded", "failed", name="security_audit_status", create_type=False
    )
    status.create(op.get_bind(), checkfirst=True)
    op.create_table(
        "security_audits",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("machine_id", sa.Uuid(), nullable=False),
        sa.Column("status", status, nullable=False),
        sa.Column("install_if_missing", sa.Boolean(), nullable=False),
        sa.Column("started_by", sa.String(length=255), nullable=True),
        sa.Column("lynis_version", sa.String(length=32), nullable=True),
        sa.Column("privileged", sa.Boolean(), nullable=True),
        sa.Column("hardening_index", sa.Integer(), nullable=True),
        sa.Column("tests_done", sa.Integer(), nullable=True),
        sa.Column("warnings", sa.JSON(), nullable=True),
        sa.Column("suggestions", sa.JSON(), nullable=True),
        sa.Column("error", sa.String(length=1024), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["machine_id"], ["machines.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_security_audits_machine_created", "security_audits", ["machine_id", "created_at"]
    )


def downgrade() -> None:
    op.drop_table("security_audits")
    op.execute("DROP TYPE IF EXISTS security_audit_status")
