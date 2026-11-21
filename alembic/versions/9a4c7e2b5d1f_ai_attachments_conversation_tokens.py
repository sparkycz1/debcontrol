"""AI conversation pictures; per-conversation token counts

Revision ID: 9a4c7e2b5d1f
Revises: 8f3b6d1e4a2c
Create Date: 2026-11-21 22:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "9a4c7e2b5d1f"
down_revision: str | None = "8f3b6d1e4a2c"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "ai_attachments",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("conversation_id", sa.Uuid(), nullable=False),
        sa.Column("message_id", sa.Uuid(), nullable=False),
        sa.Column("media_type", sa.String(length=32), nullable=False),
        sa.Column("filename", sa.String(length=255), nullable=False),
        sa.Column("size", sa.Integer(), nullable=False),
        sa.Column("data", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["conversation_id"], ["ai_conversations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["message_id"], ["ai_messages.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_ai_attachments_conversation_id"), "ai_attachments", ["conversation_id"]
    )
    op.create_index(op.f("ix_ai_attachments_message_id"), "ai_attachments", ["message_id"])
    # Existing conversations start counting at 0.
    op.add_column(
        "ai_conversations",
        sa.Column("input_tokens", sa.BigInteger(), nullable=False, server_default="0"),
    )
    op.add_column(
        "ai_conversations",
        sa.Column("output_tokens", sa.BigInteger(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_column("ai_conversations", "output_tokens")
    op.drop_column("ai_conversations", "input_tokens")
    op.drop_index(op.f("ix_ai_attachments_message_id"), table_name="ai_attachments")
    op.drop_index(op.f("ix_ai_attachments_conversation_id"), table_name="ai_attachments")
    op.drop_table("ai_attachments")
