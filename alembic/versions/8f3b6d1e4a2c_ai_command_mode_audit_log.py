"""per-user AI command mode; AI tool-output messages; security audit run log

Revision ID: 8f3b6d1e4a2c
Revises: 7e2a5c9d3f1b
Create Date: 2026-11-21 21:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "8f3b6d1e4a2c"
down_revision: str | None = "7e2a5c9d3f1b"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Every existing account keeps today's behaviour: each proposal waits
    # for a Confirm.
    op.add_column(
        "users",
        sa.Column(
            "ai_command_mode", sa.String(length=8), nullable=False, server_default="ask"
        ),
    )
    op.add_column(
        "ai_messages",
        sa.Column("is_tool_output", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    # Command output handed to the model before this release was stored as
    # an ordinary user message starting with this fixed text.
    op.execute(
        "UPDATE ai_messages SET is_tool_output = true "
        "WHERE role = 'user' AND content LIKE 'Result of the confirmed command %'"
    )
    # The whole run's log (install step, Lynis's own output and log file),
    # nullable: audits from before this release simply have none.
    op.add_column("security_audits", sa.Column("run_log", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("security_audits", "run_log")
    op.drop_column("ai_messages", "is_tool_output")
    op.drop_column("users", "ai_command_mode")
