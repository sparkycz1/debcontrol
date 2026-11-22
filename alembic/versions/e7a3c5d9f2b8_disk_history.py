"""Disks followed by serial number: their readings and events, disk
temperature and wear thresholds; timezone-aware timestamps for the
notification summary columns

`disks`, `disk_samples` and `disk_events` are new (`app.db.models.disk`).
The eight health thresholds for a disk's own temperature (by kind) and SSD
wear have server defaults, so existing settings rows get them.

`notification_rules.digest_last_sent_at` and
`notification_held_items.created_at` were created as plain `timestamp`
by d4f8b2c6e1a9, while every model timestamp is timezone-aware
(`app.db.base.Base.type_annotation_map`). Both have only ever held UTC,
so they are converted by reading the existing value as UTC.

Revision ID: e7a3c5d9f2b8
Revises: d4f8b2c6e1a9
Create Date: 2026-11-22 19:30:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "e7a3c5d9f2b8"
down_revision: str | None = "d4f8b2c6e1a9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_THRESHOLDS = (
    ("health_disk_temp_hdd_warn_celsius", "50"),
    ("health_disk_temp_hdd_critical_celsius", "60"),
    ("health_disk_temp_ssd_warn_celsius", "60"),
    ("health_disk_temp_ssd_critical_celsius", "70"),
    ("health_disk_temp_nvme_warn_celsius", "70"),
    ("health_disk_temp_nvme_critical_celsius", "80"),
    ("health_disk_wear_warn_percent", "80"),
    ("health_disk_wear_critical_percent", "95"),
)

_NAIVE_COLUMNS = (
    ("notification_rules", "digest_last_sent_at", True),
    ("notification_held_items", "created_at", False),
)


def upgrade() -> None:
    op.create_table(
        "disks",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("model", sa.String(length=255), nullable=False),
        sa.Column("serial", sa.String(length=128), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=True),
        sa.Column("rotation_rpm", sa.Integer(), nullable=True),
        sa.Column("capacity_bytes", sa.BigInteger(), nullable=True),
        sa.Column("firmware", sa.String(length=64), nullable=True),
        sa.Column("machine_id", sa.Uuid(), nullable=True),
        sa.Column("machine_name", sa.String(length=255), nullable=True),
        sa.Column("device", sa.String(length=64), nullable=True),
        sa.Column(
            "first_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("latest", sa.JSON(), nullable=True),
        sa.Column("prediction", sa.JSON(), nullable=True),
        sa.Column("event_count", sa.Integer(), server_default="0", nullable=False),
        sa.ForeignKeyConstraint(
            ["machine_id"], ["machines.id"], name="fk_disks_machine_id_machines",
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_disks"),
        sa.UniqueConstraint("model", "serial", name="uq_disks_model"),
    )
    op.create_index("ix_disks_serial", "disks", ["serial"])
    op.create_index("ix_disks_machine_id", "disks", ["machine_id"])

    op.create_table(
        "disk_samples",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("disk_id", sa.Uuid(), nullable=False),
        sa.Column("sampled_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("temperature_c", sa.Float(), nullable=True),
        sa.Column("power_on_hours", sa.Integer(), nullable=True),
        sa.Column("wear_percent", sa.Float(), nullable=True),
        sa.Column("written_bytes", sa.BigInteger(), nullable=True),
        sa.Column("counters", sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(
            ["disk_id"], ["disks.id"], name="fk_disk_samples_disk_id_disks", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_disk_samples"),
    )
    op.create_index(
        "ix_disk_samples_disk_id_sampled_at", "disk_samples", ["disk_id", "sampled_at"]
    )
    op.create_index("ix_disk_samples_sampled_at", "disk_samples", ["sampled_at"])

    op.create_table(
        "disk_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("disk_id", sa.Uuid(), nullable=False),
        sa.Column("machine_id", sa.Uuid(), nullable=True),
        sa.Column("machine_name", sa.String(length=255), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("detail", sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(
            ["disk_id"], ["disks.id"], name="fk_disk_events_disk_id_disks", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["machine_id"], ["machines.id"], name="fk_disk_events_machine_id_machines",
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_disk_events"),
    )
    op.create_index(
        "ix_disk_events_disk_id_occurred_at", "disk_events", ["disk_id", "occurred_at"]
    )
    op.create_index("ix_disk_events_occurred_at", "disk_events", ["occurred_at"])

    for column, default in _THRESHOLDS:
        op.add_column(
            "app_settings",
            sa.Column(column, sa.Integer(), server_default=default, nullable=False),
        )

    if op.get_bind().dialect.name == "postgresql":
        for table, column, nullable in _NAIVE_COLUMNS:
            op.alter_column(
                table,
                column,
                type_=sa.DateTime(timezone=True),
                existing_type=sa.DateTime(),
                existing_nullable=nullable,
                postgresql_using=f"{column} AT TIME ZONE 'UTC'",
            )


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        for table, column, nullable in _NAIVE_COLUMNS:
            op.alter_column(
                table,
                column,
                type_=sa.DateTime(),
                existing_type=sa.DateTime(timezone=True),
                existing_nullable=nullable,
                postgresql_using=f"{column} AT TIME ZONE 'UTC'",
            )
    for column, _default in reversed(_THRESHOLDS):
        op.drop_column("app_settings", column)
    op.drop_index("ix_disk_events_occurred_at", table_name="disk_events")
    op.drop_index("ix_disk_events_disk_id_occurred_at", table_name="disk_events")
    op.drop_table("disk_events")
    op.drop_index("ix_disk_samples_sampled_at", table_name="disk_samples")
    op.drop_index("ix_disk_samples_disk_id_sampled_at", table_name="disk_samples")
    op.drop_table("disk_samples")
    op.drop_index("ix_disks_machine_id", table_name="disks")
    op.drop_index("ix_disks_serial", table_name="disks")
    op.drop_table("disks")
