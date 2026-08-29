"""audit log hash chain, app settings (retention policy)

Revision ID: 4e8a1f7c3b2d
Revises: 9b2d6a4e1c7f
Create Date: 2026-08-29

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "4e8a1f7c3b2d"
down_revision: str | None = "9b2d6a4e1c7f"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    # --- Hash chain columns on the existing audit log table ---
    # Nullable: entries recorded before this migration predate hash
    # chaining and simply have nothing here — app.audit.verify_chain skips
    # them rather than treating that as tampering.
    op.add_column("audit_log_entries", sa.Column("sequence", sa.Integer(), nullable=True))
    op.add_column("audit_log_entries", sa.Column("prev_hash", sa.String(length=64), nullable=True))
    op.add_column(
        "audit_log_entries", sa.Column("entry_hash", sa.String(length=64), nullable=True)
    )
    op.create_unique_constraint(
        op.f("uq_audit_log_entries_sequence"), "audit_log_entries", ["sequence"]
    )
    op.create_index(
        op.f("ix_audit_log_entries_entry_hash"), "audit_log_entries", ["entry_hash"]
    )

    # created_at moved from a DB server_default to an app-assigned value
    # (see app/db/models/audit_log.py) so log_event() knows the exact
    # timestamp before the row is inserted, since it's part of what
    # entry_hash covers. No schema change needed for that — same column
    # type, just a different default source going forward.

    op.create_table(
        "audit_chain_state",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("last_hash", sa.String(length=64), nullable=True),
        sa.Column("entry_count", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_chain_state")),
    )

    op.create_table(
        "app_settings",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("audit_log_retention_days", sa.Integer(), nullable=True),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_app_settings")),
    )


def downgrade() -> None:
    op.drop_table("app_settings")
    op.drop_table("audit_chain_state")
    op.drop_index(op.f("ix_audit_log_entries_entry_hash"), table_name="audit_log_entries")
    op.drop_constraint(
        op.f("uq_audit_log_entries_sequence"), "audit_log_entries", type_="unique"
    )
    op.drop_column("audit_log_entries", "entry_hash")
    op.drop_column("audit_log_entries", "prev_hash")
    op.drop_column("audit_log_entries", "sequence")
