"""Docker: update policy, image check details, container event marker,
fleet vulnerability findings and accepted vulnerabilities

Revision ID: c8e0f2a4b6d7
Revises: b7d9e1f3a5c6
Create Date: 2026-10-28 18:00:00.000000

- `docker_container_settings.update_policy`: "any" (what every existing
  container's automatic update did).
- `app_settings.docker_image_check_interval_hours`: 24 (the daily check
  every instance ran so far).
- `machines.docker_image_check`, `machines.docker_events_since`,
  `docker_image_scans.raw_counts`: nullable, filled from the next check,
  monitoring sample or acceptance on.
- `docker_image_findings`: new, filled here from the stored scans'
  critical and high findings (and by every scan from now on).
- `docker_vulnerability_acceptances`: new, empty.
"""

from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa

from alembic import op

revision: str = "c8e0f2a4b6d7"
down_revision: str | None = "b7d9e1f3a5c6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SERIOUS = ("critical", "high")


def upgrade() -> None:
    op.add_column(
        "docker_container_settings",
        sa.Column("update_policy", sa.String(length=16), nullable=False, server_default="any"),
    )
    op.add_column(
        "app_settings",
        sa.Column(
            "docker_image_check_interval_hours",
            sa.Integer(),
            nullable=False,
            server_default="24",
        ),
    )
    op.add_column("machines", sa.Column("docker_image_check", sa.JSON(), nullable=True))
    op.add_column("machines", sa.Column("docker_events_since", sa.BigInteger(), nullable=True))
    op.add_column("docker_image_scans", sa.Column("raw_counts", sa.JSON(), nullable=True))

    findings = op.create_table(
        "docker_image_findings",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("machine_id", sa.Uuid(), nullable=False),
        sa.Column("vuln_id", sa.String(length=128), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("pkg", sa.String(length=255), nullable=False),
        sa.Column("installed", sa.String(length=128), nullable=False),
        sa.Column("fixed", sa.String(length=255), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["docker_image_scans.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["machine_id"], ["machines.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_docker_image_findings_vuln", "docker_image_findings", ["vuln_id"])
    op.create_index("ix_docker_image_findings_scan", "docker_image_findings", ["scan_id"])

    op.create_table(
        "docker_vulnerability_acceptances",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("vuln_id", sa.String(length=128), nullable=False),
        sa.Column("image", sa.String(length=512), nullable=False),
        sa.Column("reason", sa.String(length=500), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("vuln_id", "image", name="uq_docker_vuln_acceptances_vuln_image"),
    )
    op.create_index(
        "ix_docker_vuln_acceptances_expires", "docker_vulnerability_acceptances", ["expires_at"]
    )

    # The fleet view reads findings from their own table: fill it from the
    # scans already stored, a batch at a time.
    scans = sa.table(
        "docker_image_scans",
        sa.column("id", sa.Uuid()),
        sa.column("machine_id", sa.Uuid()),
        sa.column("vulnerabilities", sa.JSON()),
    )
    bind = op.get_bind()
    rows: list[dict[str, Any]] = []
    for scan_id, machine_id, vulnerabilities in bind.execute(
        sa.select(scans.c.id, scans.c.machine_id, scans.c.vulnerabilities)
    ):
        for item in vulnerabilities or []:
            if not isinstance(item, dict) or item.get("severity") not in _SERIOUS:
                continue
            vuln_id = str(item.get("id") or "")[:128]
            if not vuln_id:
                continue
            rows.append(
                {
                    "scan_id": scan_id,
                    "machine_id": machine_id,
                    "vuln_id": vuln_id,
                    "severity": str(item["severity"]),
                    "pkg": str(item.get("pkg") or "")[:255],
                    "installed": str(item.get("installed") or "")[:128],
                    "fixed": str(item.get("fixed") or "")[:255],
                }
            )
        if len(rows) >= 5000:
            op.bulk_insert(findings, rows)
            rows = []
    if rows:
        op.bulk_insert(findings, rows)


def downgrade() -> None:
    op.drop_index(
        "ix_docker_vuln_acceptances_expires", table_name="docker_vulnerability_acceptances"
    )
    op.drop_table("docker_vulnerability_acceptances")
    op.drop_index("ix_docker_image_findings_scan", table_name="docker_image_findings")
    op.drop_index("ix_docker_image_findings_vuln", table_name="docker_image_findings")
    op.drop_table("docker_image_findings")
    op.drop_column("docker_image_scans", "raw_counts")
    op.drop_column("machines", "docker_events_since")
    op.drop_column("machines", "docker_image_check")
    op.drop_column("app_settings", "docker_image_check_interval_hours")
    op.drop_column("docker_container_settings", "update_policy")
