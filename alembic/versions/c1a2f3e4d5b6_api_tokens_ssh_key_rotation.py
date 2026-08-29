"""per-user API tokens, SSH identity rotation (pending key columns)

Revision ID: c1a2f3e4d5b6
Revises: 804c4b8e2824
Create Date: 2026-08-29

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c1a2f3e4d5b6"
down_revision: str | None = "804c4b8e2824"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.create_table(
        "api_tokens",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("token_prefix", sa.String(length=12), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name=op.f("fk_api_tokens_user_id_users"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_api_tokens")),
        sa.UniqueConstraint("token_hash", name=op.f("uq_api_tokens_token_hash")),
    )
    op.create_index(op.f("ix_api_tokens_user_id"), "api_tokens", ["user_id"])

    # --- SSH key rotation: a second, not-yet-active keypair alongside the
    # active one — see app/db/models/ssh_identity.py. ---
    op.add_column("ssh_identity", sa.Column("pending_public_key", sa.Text(), nullable=True))
    op.add_column(
        "ssh_identity", sa.Column("pending_private_key_encrypted", sa.LargeBinary(), nullable=True)
    )
    op.add_column(
        "ssh_identity", sa.Column("pending_fingerprint", sa.String(length=255), nullable=True)
    )
    op.add_column(
        "ssh_identity",
        sa.Column("pending_generated_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("ssh_identity", "pending_generated_at")
    op.drop_column("ssh_identity", "pending_fingerprint")
    op.drop_column("ssh_identity", "pending_private_key_encrypted")
    op.drop_column("ssh_identity", "pending_public_key")

    op.drop_index(op.f("ix_api_tokens_user_id"), table_name="api_tokens")
    op.drop_table("api_tokens")
