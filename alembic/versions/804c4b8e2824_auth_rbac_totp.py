"""authentication, RBAC (roles/permissions), sessions, TOTP, LDAP/OIDC settings

Revision ID: 804c4b8e2824
Revises: 4e8a1f7c3b2d
Create Date: 2026-08-29

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "804c4b8e2824"
down_revision: str | None = "4e8a1f7c3b2d"
branch_labels: Sequence[str] | str | None = None
depends_on: Sequence[str] | str | None = None

_PERMISSIONS = (
    "machine.view",
    "machine.manage",
    "group.view",
    "group.manage",
    "action.updates",
    "action.power",
    "scheduling.view",
    "scheduling.manage",
    "audit.view",
    "settings.view",
    "settings.manage",
    "user.manage",
)


def upgrade() -> None:
    op.create_table(
        "roles",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("description", sa.String(length=500), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            onupdate=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_roles")),
        sa.UniqueConstraint("name", name=op.f("uq_roles_name")),
    )

    op.create_table(
        "role_permissions",
        sa.Column("role_id", sa.Uuid(), nullable=False),
        sa.Column("permission", sa.Enum(*_PERMISSIONS, name="permission"), nullable=False),
        sa.ForeignKeyConstraint(
            ["role_id"],
            ["roles.id"],
            name=op.f("fk_role_permissions_role_id_roles"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("role_id", "permission", name=op.f("pk_role_permissions")),
    )

    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("username", sa.String(length=64), nullable=False),
        sa.Column("display_name", sa.String(length=255), nullable=True),
        sa.Column(
            "auth_provider", sa.Enum("local", "ldap", "oidc", name="auth_provider"), nullable=False
        ),
        sa.Column("password_hash", sa.String(length=255), nullable=True),
        sa.Column("must_change_password", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("totp_secret_encrypted", sa.LargeBinary(), nullable=True),
        sa.Column("totp_enabled", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("totp_confirmed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failed_login_attempts", sa.Integer(), server_default="0", nullable=False),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("role_id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            onupdate=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["role_id"], ["roles.id"], name=op.f("fk_users_role_id_roles")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_users")),
        sa.UniqueConstraint("username", name=op.f("uq_users_username")),
    )

    op.create_table(
        "user_sessions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("user_agent", sa.String(length=255), nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_user_sessions_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_user_sessions")),
        sa.UniqueConstraint("token_hash", name=op.f("uq_user_sessions_token_hash")),
    )
    op.create_index(op.f("ix_user_sessions_user_id"), "user_sessions", ["user_id"])

    op.create_table(
        "totp_recovery_codes",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("code_hash", sa.String(length=255), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_totp_recovery_codes_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_totp_recovery_codes")),
    )
    op.create_index(op.f("ix_totp_recovery_codes_user_id"), "totp_recovery_codes", ["user_id"])

    # --- LDAP/OIDC login config on the existing app_settings singleton ---
    op.add_column(
        "app_settings",
        sa.Column("ldap_enabled", sa.Boolean(), server_default=sa.false(), nullable=False),
    )
    op.add_column(
        "app_settings", sa.Column("ldap_server_uri", sa.String(length=255), nullable=True)
    )
    op.add_column(
        "app_settings",
        sa.Column("ldap_use_starttls", sa.Boolean(), server_default=sa.false(), nullable=False),
    )
    op.add_column("app_settings", sa.Column("ldap_bind_dn", sa.String(length=255), nullable=True))
    op.add_column(
        "app_settings", sa.Column("ldap_bind_password_encrypted", sa.LargeBinary(), nullable=True)
    )
    op.add_column(
        "app_settings", sa.Column("ldap_user_search_base", sa.String(length=255), nullable=True)
    )
    op.add_column(
        "app_settings",
        sa.Column(
            "ldap_user_search_filter",
            sa.String(length=255),
            server_default="(uid={username})",
            nullable=False,
        ),
    )
    op.add_column(
        "app_settings",
        sa.Column("ldap_connect_timeout_seconds", sa.Integer(), server_default="5", nullable=False),
    )
    op.add_column(
        "app_settings",
        sa.Column("oidc_enabled", sa.Boolean(), server_default=sa.false(), nullable=False),
    )
    op.add_column(
        "app_settings", sa.Column("oidc_issuer_url", sa.String(length=500), nullable=True)
    )
    op.add_column("app_settings", sa.Column("oidc_client_id", sa.String(length=255), nullable=True))
    op.add_column(
        "app_settings", sa.Column("oidc_client_secret_encrypted", sa.LargeBinary(), nullable=True)
    )
    op.add_column(
        "app_settings",
        sa.Column(
            "oidc_username_claim", sa.String(length=100), server_default="email", nullable=False
        ),
    )
    op.add_column(
        "app_settings",
        sa.Column(
            "oidc_scopes",
            sa.String(length=255),
            server_default="openid email profile",
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_column("app_settings", "oidc_scopes")
    op.drop_column("app_settings", "oidc_username_claim")
    op.drop_column("app_settings", "oidc_client_secret_encrypted")
    op.drop_column("app_settings", "oidc_client_id")
    op.drop_column("app_settings", "oidc_issuer_url")
    op.drop_column("app_settings", "oidc_enabled")
    op.drop_column("app_settings", "ldap_connect_timeout_seconds")
    op.drop_column("app_settings", "ldap_user_search_filter")
    op.drop_column("app_settings", "ldap_user_search_base")
    op.drop_column("app_settings", "ldap_bind_password_encrypted")
    op.drop_column("app_settings", "ldap_bind_dn")
    op.drop_column("app_settings", "ldap_use_starttls")
    op.drop_column("app_settings", "ldap_server_uri")
    op.drop_column("app_settings", "ldap_enabled")

    op.drop_index(op.f("ix_totp_recovery_codes_user_id"), table_name="totp_recovery_codes")
    op.drop_table("totp_recovery_codes")

    op.drop_index(op.f("ix_user_sessions_user_id"), table_name="user_sessions")
    op.drop_table("user_sessions")

    op.drop_table("users")
    sa.Enum(name="auth_provider").drop(op.get_bind(), checkfirst=True)

    op.drop_table("role_permissions")
    sa.Enum(name="permission").drop(op.get_bind(), checkfirst=True)

    op.drop_table("roles")
