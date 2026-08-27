"""machine facts, ssh identity, pending machines

Revision ID: 79297267a7be
Revises: f72dca97d347
Create Date: 2026-08-27

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "79297267a7be"
down_revision: str | None = "f72dca97d347"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    # --- machines: rename hostname -> ip_address, add name + facts columns ---
    op.alter_column("machines", "hostname", new_column_name="ip_address")

    op.add_column("machines", sa.Column("name", sa.String(length=255), nullable=True))
    # Backfill: give existing rows a name so the column can become NOT NULL.
    op.execute("UPDATE machines SET name = ip_address WHERE name IS NULL")
    op.alter_column("machines", "name", nullable=False)

    op.add_column(
        "machines", sa.Column("discovered_hostname", sa.String(length=255), nullable=True)
    )
    op.add_column("machines", sa.Column("os_version", sa.String(length=255), nullable=True))
    op.add_column("machines", sa.Column("kernel_version", sa.String(length=255), nullable=True))
    op.add_column("machines", sa.Column("cpu_cores", sa.Integer(), nullable=True))
    op.add_column("machines", sa.Column("ram_bytes", sa.BigInteger(), nullable=True))
    op.add_column("machines", sa.Column("disks", sa.JSON(), nullable=True))
    op.add_column(
        "machines", sa.Column("facts_updated_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column("machines", sa.Column("is_reachable", sa.Boolean(), nullable=True))
    op.add_column("machines", sa.Column("last_ping_at", sa.DateTime(timezone=True), nullable=True))

    # auth_method: 'private_key' -> 'ssh_key' (rename in place — existing
    # rows keep their meaning, no data migration needed).
    op.execute("ALTER TYPE auth_method RENAME VALUE 'private_key' TO 'ssh_key'")

    # --- ssh_identity: singleton row holding the app's own SSH keypair ---
    op.create_table(
        "ssh_identity",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("public_key", sa.Text(), nullable=False),
        sa.Column("private_key_encrypted", sa.LargeBinary(), nullable=False),
        sa.Column("fingerprint", sa.String(length=255), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ssh_identity")),
    )

    # --- pending_machines: self-registrations awaiting review ---
    op.create_table(
        "pending_machines",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("ip_address", sa.String(length=255), nullable=False),
        sa.Column("reported_hostname", sa.String(length=255), nullable=True),
        sa.Column("os_version", sa.String(length=255), nullable=True),
        sa.Column("kernel_version", sa.String(length=255), nullable=True),
        sa.Column("cpu_cores", sa.Integer(), nullable=True),
        sa.Column("ram_bytes", sa.BigInteger(), nullable=True),
        sa.Column("disks", sa.JSON(), nullable=True),
        sa.Column("source_ip", sa.String(length=255), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_pending_machines")),
    )


def downgrade() -> None:
    op.drop_table("pending_machines")
    op.drop_table("ssh_identity")

    op.execute("ALTER TYPE auth_method RENAME VALUE 'ssh_key' TO 'private_key'")

    op.drop_column("machines", "last_ping_at")
    op.drop_column("machines", "is_reachable")
    op.drop_column("machines", "facts_updated_at")
    op.drop_column("machines", "disks")
    op.drop_column("machines", "ram_bytes")
    op.drop_column("machines", "cpu_cores")
    op.drop_column("machines", "kernel_version")
    op.drop_column("machines", "os_version")
    op.drop_column("machines", "discovered_hostname")
    op.drop_column("machines", "name")

    op.alter_column("machines", "ip_address", new_column_name="hostname")
