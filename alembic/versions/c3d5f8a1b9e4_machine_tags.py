"""free-form machine tags (tags, machine_tags)

Revision ID: c3d5f8a1b9e4
Revises: b7c9e2a4f6d1
Create Date: 2026-09-04

No backfill: a brand-new, empty tags table — every existing machine simply
has zero tags until someone adds one. See app/db/models/machine_tag.py.

"""

from __future__ import annotations

import uuid
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c3d5f8a1b9e4"
down_revision: str | None = "b7c9e2a4f6d1"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.create_table(
        "tags",
        sa.Column("id", sa.Uuid(), primary_key=True, default=uuid.uuid4),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_index("ix_tags_name", "tags", ["name"], unique=True)

    op.create_table(
        "machine_tags",
        sa.Column("machine_id", sa.Uuid(), nullable=False),
        sa.Column("tag_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["machine_id"],
            ["machines.id"],
            name=op.f("fk_machine_tags_machine_id_machines"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tag_id"], ["tags.id"], name=op.f("fk_machine_tags_tag_id_tags"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("machine_id", "tag_id", name=op.f("pk_machine_tags")),
    )


def downgrade() -> None:
    op.drop_table("machine_tags")
    op.drop_index("ix_tags_name", table_name="tags")
    op.drop_table("tags")
