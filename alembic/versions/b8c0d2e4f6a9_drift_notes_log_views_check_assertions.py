"""configuration drift, machine notes, saved log views, check assertions

- `machines`: `listening_ports`, `admin_users`, `login_users` (nullable
  JSON, filled by the next facts refresh — until then drift detection
  treats them as unknown and stays quiet).
- `machine_changes`: detected configuration changes / new security updates.
- `machine_notes`: dated notes on a machine's History tab.
- `saved_log_views`: per-account saved Logs tab filters.
- `endpoint_checks`: `unexpected_body`, `json_path`, `json_expected`,
  `max_latency_ms`, `sla_target_percent` (all nullable — existing checks
  behave exactly as before).
- `audit_log_entries`: an index on (`target_id`, `created_at`) for the
  History tab's "entries about this machine" read.

Revision ID: b8c0d2e4f6a9
Revises: a7b9c1d3e5f8
Create Date: 2026-09-26

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b8c0d2e4f6a9"
down_revision: str | None = "a7b9c1d3e5f8"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column("machines", sa.Column("listening_ports", sa.JSON(), nullable=True))
    op.add_column("machines", sa.Column("admin_users", sa.JSON(), nullable=True))
    op.add_column("machines", sa.Column("login_users", sa.JSON(), nullable=True))

    op.add_column(
        "endpoint_checks", sa.Column("unexpected_body", sa.String(length=200), nullable=True)
    )
    op.add_column("endpoint_checks", sa.Column("json_path", sa.String(length=200), nullable=True))
    op.add_column(
        "endpoint_checks", sa.Column("json_expected", sa.String(length=200), nullable=True)
    )
    op.add_column("endpoint_checks", sa.Column("max_latency_ms", sa.Integer(), nullable=True))
    op.add_column("endpoint_checks", sa.Column("sla_target_percent", sa.Float(), nullable=True))

    op.create_table(
        "machine_changes",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("machine_id", sa.Uuid(), nullable=False),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("category", sa.String(length=16), nullable=False),
        sa.Column("field", sa.String(length=32), nullable=False),
        sa.Column("old_value", sa.Text(), nullable=True),
        sa.Column("new_value", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["machine_id"],
            ["machines.id"],
            name=op.f("fk_machine_changes_machine_id_machines"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_machine_changes")),
    )
    op.create_index(
        "ix_machine_changes_machine_id_detected_at",
        "machine_changes",
        ["machine_id", "detected_at"],
    )
    op.create_index("ix_machine_changes_detected_at", "machine_changes", ["detected_at"])

    op.create_table(
        "machine_notes",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("machine_id", sa.Uuid(), nullable=False),
        sa.Column("author", sa.String(length=255), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["machine_id"],
            ["machines.id"],
            name=op.f("fk_machine_notes_machine_id_machines"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_machine_notes")),
    )
    op.create_index(
        "ix_machine_notes_machine_id_created_at", "machine_notes", ["machine_id", "created_at"]
    )

    op.create_table(
        "saved_log_views",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("query_string", sa.String(length=1000), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_saved_log_views_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_saved_log_views")),
        sa.UniqueConstraint("user_id", "name", name="uq_saved_log_views_user_id_name"),
    )
    op.create_index("ix_saved_log_views_user_id", "saved_log_views", ["user_id"])

    op.create_index(
        "ix_audit_log_entries_target_id_created_at",
        "audit_log_entries",
        ["target_id", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_audit_log_entries_target_id_created_at", table_name="audit_log_entries")
    op.drop_index("ix_saved_log_views_user_id", table_name="saved_log_views")
    op.drop_table("saved_log_views")
    op.drop_index("ix_machine_notes_machine_id_created_at", table_name="machine_notes")
    op.drop_table("machine_notes")
    op.drop_index("ix_machine_changes_detected_at", table_name="machine_changes")
    op.drop_index("ix_machine_changes_machine_id_detected_at", table_name="machine_changes")
    op.drop_table("machine_changes")
    for column in (
        "sla_target_percent",
        "max_latency_ms",
        "json_expected",
        "json_path",
        "unexpected_body",
    ):
        op.drop_column("endpoint_checks", column)
    for column in ("login_users", "admin_users", "listening_ports"):
        op.drop_column("machines", column)
