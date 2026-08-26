"""initial schema — machines

Revision ID: a223c4d67523
Revises:
Create Date: 2026-08-26

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a223c4d67523"
down_revision: str | None = None
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None

auth_method_enum = postgresql.ENUM("password", "private_key", name="auth_method")


def upgrade() -> None:
    auth_method_enum.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "machines",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("username", sa.String(length=255), nullable=False),
        sa.Column(
            "auth_method",
            postgresql.ENUM("password", "private_key", name="auth_method", create_type=False),
            nullable=False,
        ),
        sa.Column("secret_encrypted", sa.LargeBinary(), nullable=True),
        sa.Column("host_key_fingerprint", sa.String(length=255), nullable=True),
        sa.Column("description", sa.String(length=1024), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False),
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
        sa.PrimaryKeyConstraint("id", name=op.f("pk_machines")),
    )


def downgrade() -> None:
    op.drop_table("machines")
    auth_method_enum.drop(op.get_bind(), checkfirst=True)
