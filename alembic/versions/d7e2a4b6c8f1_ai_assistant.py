"""AI assistant: provider configs, fetched models, conversations, usage

Revision ID: d7e2a4b6c8f1
Revises: c1d2e3f4a5b6
Create Date: 2026-08-30

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d7e2a4b6c8f1"
down_revision: str | None = "c1d2e3f4a5b6"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None

# Used by two tables (ai_provider_configs.kind and
# ai_usage_records.provider_kind), so it's created once up front and
# referenced with create_type=False afterwards — same pattern the initial
# schema uses for `auth_method`.
ai_provider_kind_enum = postgresql.ENUM(
    "anthropic",
    "openai",
    "gemini",
    "openrouter",
    "openai_compatible",
    name="ai_provider_kind",
)


def _kind_column_type() -> postgresql.ENUM:
    return postgresql.ENUM(
        "anthropic",
        "openai",
        "gemini",
        "openrouter",
        "openai_compatible",
        name="ai_provider_kind",
        create_type=False,
    )


def upgrade() -> None:
    ai_provider_kind_enum.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "ai_provider_configs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("kind", _kind_column_type(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("api_key_encrypted", sa.LargeBinary(), nullable=True),
        sa.Column("base_url", sa.String(length=500), nullable=True),
        sa.Column("models_fetched_at", sa.DateTime(timezone=True), nullable=True),
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
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ai_provider_configs")),
        sa.UniqueConstraint("kind", name=op.f("uq_ai_provider_configs_kind")),
    )

    op.create_table(
        "ai_models",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("provider_id", sa.Uuid(), nullable=False),
        sa.Column("model_id", sa.String(length=255), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(
            ["provider_id"],
            ["ai_provider_configs.id"],
            name=op.f("fk_ai_models_provider_id_ai_provider_configs"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ai_models")),
        sa.UniqueConstraint("provider_id", "model_id", name="uq_ai_models_provider_id"),
    )

    op.create_table(
        "ai_conversations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("provider_id", sa.Uuid(), nullable=False),
        sa.Column("model_id", sa.String(length=255), nullable=False),
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
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_ai_conversations_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["provider_id"],
            ["ai_provider_configs.id"],
            name=op.f("fk_ai_conversations_provider_id_ai_provider_configs"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ai_conversations")),
    )
    op.create_index(op.f("ix_ai_conversations_user_id"), "ai_conversations", ["user_id"])

    ai_message_role_enum = sa.Enum("user", "assistant", name="ai_message_role")
    op.create_table(
        "ai_messages",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("conversation_id", sa.Uuid(), nullable=False),
        sa.Column("role", ai_message_role_enum, nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("provider_native", sa.JSON(), nullable=True),
        sa.Column("pending_actions", sa.JSON(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["conversation_id"],
            ["ai_conversations.id"],
            name=op.f("fk_ai_messages_conversation_id_ai_conversations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ai_messages")),
    )
    op.create_index(op.f("ix_ai_messages_conversation_id"), "ai_messages", ["conversation_id"])

    op.create_table(
        "ai_usage_records",
        sa.Column("id", sa.Uuid(), nullable=False),
        # SET NULL, not CASCADE: the token limits are global, so deleting an
        # account must not retroactively free up budget that was spent.
        sa.Column("user_id", sa.Uuid(), nullable=True),
        sa.Column("provider_kind", _kind_column_type(), nullable=False),
        sa.Column("model_id", sa.String(length=255), nullable=False),
        sa.Column("input_tokens", sa.Integer(), nullable=False),
        sa.Column("output_tokens", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_ai_usage_records_user_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ai_usage_records")),
    )
    op.create_index(op.f("ix_ai_usage_records_created_at"), "ai_usage_records", ["created_at"])

    for column in ("ai_daily_token_limit", "ai_weekly_token_limit", "ai_monthly_token_limit"):
        op.add_column("app_settings", sa.Column(column, sa.Integer(), nullable=True))


def downgrade() -> None:
    for column in ("ai_monthly_token_limit", "ai_weekly_token_limit", "ai_daily_token_limit"):
        op.drop_column("app_settings", column)

    op.drop_index(op.f("ix_ai_usage_records_created_at"), table_name="ai_usage_records")
    op.drop_table("ai_usage_records")

    op.drop_index(op.f("ix_ai_messages_conversation_id"), table_name="ai_messages")
    op.drop_table("ai_messages")
    sa.Enum(name="ai_message_role").drop(op.get_bind(), checkfirst=True)

    op.drop_index(op.f("ix_ai_conversations_user_id"), table_name="ai_conversations")
    op.drop_table("ai_conversations")

    op.drop_table("ai_models")
    op.drop_table("ai_provider_configs")

    sa.Enum(name="ai_provider_kind").drop(op.get_bind(), checkfirst=True)
