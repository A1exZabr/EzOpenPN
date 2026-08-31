"""Create the initial durable control schema."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001_initial"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _timestamps() -> tuple[sa.Column, sa.Column]:
    return (
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
    )


def upgrade() -> None:
    op.create_table(
        "admins",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("login", sa.String(length=128), nullable=False),
        sa.Column("password_hash", sa.String(length=512), nullable=False),
        sa.Column("singleton_key", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("session_version", sa.Integer(), nullable=False, server_default="1"),
        *_timestamps(),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "length(login) BETWEEN 1 AND 128", name="ck_admins_login_length"
        ),
        sa.CheckConstraint("session_version >= 1", name="ck_admins_session_version"),
        sa.CheckConstraint("singleton_key = 1", name="ck_admins_singleton_key"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("login", name="uq_admins_login"),
        sa.UniqueConstraint("singleton_key", name="uq_admins_singleton_key"),
    )
    op.create_table(
        "login_throttles",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("scope", sa.String(length=16), nullable=False),
        sa.Column("key_digest", sa.LargeBinary(length=32), nullable=False),
        sa.Column("failure_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("window_started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_failed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("blocked_until", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("scope IN ('ip', 'login')", name="ck_login_throttles_scope"),
        sa.CheckConstraint("failure_count >= 0", name="ck_login_throttles_failure_count"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scope", "key_digest", name="uq_login_throttles_scope_key"),
    )
    op.create_index(
        "ix_login_throttles_blocked_until", "login_throttles", ["blocked_until"]
    )
    op.create_table(
        "profiles",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column(
            "state",
            sa.Enum(
                "pending",
                "active",
                "disabled",
                "error",
                name="profile_state",
                native_enum=False,
                create_constraint=False,
            ),
            nullable=False,
        ),
        sa.Column("runtime_id", sa.String(length=28), nullable=False),
        sa.Column("wrapped_profile_key", sa.LargeBinary(), nullable=True),
        sa.Column("user_id_ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("hysteria_secret_ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("subscription_token_ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("last_error_code", sa.String(length=64), nullable=True),
        *_timestamps(),
        sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "state IN ('pending', 'active', 'disabled', 'error')",
            name="ck_profiles_state",
        ),
        sa.CheckConstraint("length(name) BETWEEN 1 AND 64", name="ck_profiles_name_length"),
        sa.CheckConstraint("length(runtime_id) = 28", name="ck_profiles_runtime_id_length"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("runtime_id", name="uq_profiles_runtime_id"),
    )
    op.create_index("ix_profiles_state", "profiles", ["state"])
    op.create_table(
        "system_state",
        sa.Column("key", sa.String(length=128), nullable=False),
        sa.Column("value_json", sa.Text(), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "length(key) BETWEEN 1 AND 128", name="ck_system_state_key_length"
        ),
        sa.PrimaryKeyConstraint("key"),
    )
    op.create_table(
        "admin_sessions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("admin_id", sa.String(length=36), nullable=False),
        sa.Column("token_digest", sa.LargeBinary(length=32), nullable=False),
        sa.Column("csrf_digest", sa.LargeBinary(length=32), nullable=False),
        sa.Column("session_version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("idle_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("absolute_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("session_version >= 1", name="ck_admin_sessions_version"),
        sa.ForeignKeyConstraint(["admin_id"], ["admins.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_digest", name="uq_admin_sessions_token_digest"),
    )
    op.create_index("ix_admin_sessions_admin_id", "admin_sessions", ["admin_id"])
    op.create_index(
        "ix_admin_sessions_absolute_expiry", "admin_sessions", ["absolute_expires_at"]
    )
    op.create_table(
        "audit_events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("actor_admin_id", sa.String(length=36), nullable=True),
        sa.Column("subject_id", sa.String(length=64), nullable=True),
        sa.Column("details_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column(
            "occurred_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "length(event_type) BETWEEN 1 AND 64", name="ck_audit_events_type_length"
        ),
        sa.ForeignKeyConstraint(["actor_admin_id"], ["admins.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_events_occurred_at", "audit_events", ["occurred_at"])
    op.create_table(
        "profile_lookups",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("profile_id", sa.String(length=36), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("lookup_digest", sa.LargeBinary(length=32), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "length(lookup_digest) = 32", name="ck_profile_lookups_digest_length"
        ),
        sa.ForeignKeyConstraint(["profile_id"], ["profiles.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("lookup_digest", name="uq_profile_lookups_digest"),
        sa.UniqueConstraint("profile_id", "kind", name="uq_profile_lookups_profile_kind"),
    )
    op.create_index("ix_profile_lookups_profile_id", "profile_lookups", ["profile_id"])


def downgrade() -> None:
    op.drop_index("ix_profile_lookups_profile_id", table_name="profile_lookups")
    op.drop_table("profile_lookups")
    op.drop_index("ix_audit_events_occurred_at", table_name="audit_events")
    op.drop_table("audit_events")
    op.drop_index("ix_admin_sessions_absolute_expiry", table_name="admin_sessions")
    op.drop_index("ix_admin_sessions_admin_id", table_name="admin_sessions")
    op.drop_table("admin_sessions")
    op.drop_table("system_state")
    op.drop_index("ix_profiles_state", table_name="profiles")
    op.drop_table("profiles")
    op.drop_index("ix_login_throttles_blocked_until", table_name="login_throttles")
    op.drop_table("login_throttles")
    op.drop_table("admins")
