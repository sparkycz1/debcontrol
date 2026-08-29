"""installed-package snapshot (apt/flatpak/snap) + flatpak/snap update counts

Revision ID: b4e7a1f9c2d6
Revises: d2b3f4a5e6c7
Create Date: 2026-08-29

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b4e7a1f9c2d6"
down_revision: str | None = "d2b3f4a5e6c7"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None


def upgrade() -> None:
    op.add_column(
        "machines", sa.Column("flatpak_upgradable_count", sa.Integer(), nullable=True)
    )
    op.add_column("machines", sa.Column("snap_upgradable_count", sa.Integer(), nullable=True))
    op.add_column(
        "machines", sa.Column("packages_updated_at", sa.DateTime(timezone=True), nullable=True)
    )

    package_source = sa.Enum("apt", "flatpak", "snap", name="package_source")
    package_source.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "machine_packages",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("machine_id", sa.Uuid(), nullable=False),
        sa.Column("source", package_source, nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("version", sa.String(length=255), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["machine_id"],
            ["machines.id"],
            name=op.f("fk_machine_packages_machine_id_machines"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_machine_packages")),
    )
    op.create_index(op.f("ix_machine_packages_machine_id"), "machine_packages", ["machine_id"])
    op.create_index(
        "ix_machine_packages_machine_id_source", "machine_packages", ["machine_id", "source"]
    )


def downgrade() -> None:
    op.drop_index("ix_machine_packages_machine_id_source", table_name="machine_packages")
    op.drop_index(op.f("ix_machine_packages_machine_id"), table_name="machine_packages")
    op.drop_table("machine_packages")
    sa.Enum(name="package_source").drop(op.get_bind(), checkfirst=True)

    op.drop_column("machines", "packages_updated_at")
    op.drop_column("machines", "snap_upgradable_count")
    op.drop_column("machines", "flatpak_upgradable_count")
