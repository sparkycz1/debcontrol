"""BRIN indexes on the time columns of the sample tables.

- machine_monitoring_samples.sampled_at and
  machine_reachability_samples.checked_at get a BRIN index (rows arrive in
  time order, so a few pages cover millions of rows).
- endpoint_check_results.checked_at: its B-tree index is replaced by a BRIN
  one (only the retention purge's cutoff uses it).

Indexes only, no data change. Building a BRIN index is one sequential scan.

Revision ID: e1a3c5e7f9b2
Revises: d9f1a3b5c7e9
Create Date: 2026-10-29
"""

from collections.abc import Sequence

from alembic import op

revision: str = "e1a3c5e7f9b2"
down_revision: str | None = "d9f1a3b5c7e9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(
        "ix_machine_monitoring_samples_sampled_at_brin",
        "machine_monitoring_samples",
        ["sampled_at"],
        postgresql_using="brin",
    )
    op.create_index(
        "ix_machine_reachability_samples_checked_at_brin",
        "machine_reachability_samples",
        ["checked_at"],
        postgresql_using="brin",
    )
    op.create_index(
        "ix_endpoint_check_results_checked_at_brin",
        "endpoint_check_results",
        ["checked_at"],
        postgresql_using="brin",
    )
    op.drop_index("ix_endpoint_check_results_checked_at", table_name="endpoint_check_results")


def downgrade() -> None:
    op.create_index(
        "ix_endpoint_check_results_checked_at", "endpoint_check_results", ["checked_at"]
    )
    op.drop_index("ix_endpoint_check_results_checked_at_brin", table_name="endpoint_check_results")
    op.drop_index(
        "ix_machine_reachability_samples_checked_at_brin",
        table_name="machine_reachability_samples",
    )
    op.drop_index(
        "ix_machine_monitoring_samples_sampled_at_brin", table_name="machine_monitoring_samples"
    )
