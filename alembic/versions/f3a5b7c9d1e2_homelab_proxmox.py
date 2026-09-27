"""homelab/Proxmox round: SSH connection reuse, Proxmox VE/ZFS data, ARC-aware
memory, held packages, failed units, reboot-if-needed/rolling updates,
scheduled task time zones, push notification channels

Revision ID: f3a5b7c9d1e2
Revises: e2f4a6b8c0d1
Create Date: 2026-09-27

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f3a5b7c9d1e2"
down_revision: str | None = "e2f4a6b8c0d1"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None

_MACHINE_JSON_COLUMNS = (
    "pve_storage",
    "pve_backups",
    "pve_guests",
    "zfs_pools",
    "apt_held_packages",
    "failed_units",
)


def upgrade() -> None:
    # Every new column is nullable or has a server default, so existing rows
    # stay valid and behave as before (no time zone = UTC, no reboot after
    # an update, no connection reuse beyond the 15-minute default).
    op.add_column(
        "app_settings",
        sa.Column(
            "ssh_connection_reuse_minutes", sa.Integer(), nullable=False, server_default="15"
        ),
    )
    op.add_column("machines", sa.Column("pve_version", sa.String(length=32), nullable=True))
    for name in _MACHINE_JSON_COLUMNS:
        op.add_column("machines", sa.Column(name, sa.JSON(), nullable=True))
    op.add_column(
        "machine_monitoring_samples", sa.Column("ram_arc_bytes", sa.BigInteger(), nullable=True)
    )
    op.add_column(
        "machine_monitoring_samples",
        sa.Column("ram_cache_bytes", sa.BigInteger(), nullable=True),
    )
    op.add_column(
        "machine_update_runs",
        sa.Column(
            "reboot_if_required", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
    )
    op.add_column(
        "machine_update_runs", sa.Column("reboot_outcome", sa.String(length=16), nullable=True)
    )
    op.add_column(
        "machine_update_runs", sa.Column("rollout_position", sa.Integer(), nullable=True)
    )
    op.add_column(
        "scheduled_tasks", sa.Column("timezone", sa.String(length=64), nullable=True)
    )
    op.add_column(
        "scheduled_tasks",
        sa.Column(
            "require_maintenance_window",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.add_column(
        "notification_rules",
        sa.Column("channel_token_encrypted", sa.LargeBinary(), nullable=True),
    )
    op.add_column(
        "notification_rules",
        sa.Column("channel_recipient", sa.String(length=255), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("notification_rules", "channel_recipient")
    op.drop_column("notification_rules", "channel_token_encrypted")
    op.drop_column("scheduled_tasks", "require_maintenance_window")
    op.drop_column("scheduled_tasks", "timezone")
    op.drop_column("machine_update_runs", "rollout_position")
    op.drop_column("machine_update_runs", "reboot_outcome")
    op.drop_column("machine_update_runs", "reboot_if_required")
    op.drop_column("machine_monitoring_samples", "ram_cache_bytes")
    op.drop_column("machine_monitoring_samples", "ram_arc_bytes")
    for name in reversed(_MACHINE_JSON_COLUMNS):
        op.drop_column("machines", name)
    op.drop_column("machines", "pve_version")
    op.drop_column("app_settings", "ssh_connection_reuse_minutes")
