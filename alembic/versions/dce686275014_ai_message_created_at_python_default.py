"""ai_messages.created_at: drop server_default, assigned in Python instead

Revision ID: dce686275014
Revises: 5b78c5e64719
Create Date: 2026-09-01

`AiMessage.created_at` used `server_default=func.now()`, which only has
*second* resolution in SQLite (what the test suite runs against) — two
messages inserted within the same second tied on `created_at`, and
`order_by(created_at, id)` fell back to sorting by `id`, a random UUID
unrelated to insertion order. This surfaced as a real, order-dependent
test failure once the conversation page started asking "is the *last*
message an assistant reply yet?" (`app.web.routes.ai._is_awaiting_reply`).
Real Postgres deployments were never actually broken by this (its `now()`
has microsecond resolution, so a same-timestamp collision between a
human's message and a reply that took an actual network round-trip is
vanishingly unlikely) — this is a preventive fix, not a data repair.

Now assigned in Python (`datetime.now(UTC)`, microsecond resolution
everywhere) instead, same mechanism `AuditLogEntry.created_at` already
uses (for an unrelated reason — see that model's own docstring). No data
migration: existing rows keep whatever timestamp they already have; only
new inserts are affected, and only the DB-side default is dropped here —
the column itself, its type, and its `NOT NULL` constraint are unchanged.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "dce686275014"
down_revision: str | None = "5b78c5e64719"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.alter_column("ai_messages", "created_at", server_default=None)


def downgrade() -> None:
    op.alter_column("ai_messages", "created_at", server_default=sa.text("now()"))
