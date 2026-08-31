from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import (
    CheckConstraint,
    Enum,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    TypeDecorator,
    UniqueConstraint,
    func,
)
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.sql.type_api import TypeEngine
from sqlalchemy.types import DateTime


class Base(DeclarativeBase):
    pass


class UTCDateTime(TypeDecorator[datetime]):
    """Store UTC without an offset in SQLite and restore an aware value."""

    impl = DateTime
    cache_ok = True

    def load_dialect_impl(self, dialect: Dialect) -> TypeEngine[datetime]:
        return dialect.type_descriptor(DateTime(timezone=False))

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        del dialect
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamps must include a timezone")
        return value.astimezone(UTC).replace(tzinfo=None)

    def process_result_value(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        del dialect
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


class ProfileState(StrEnum):
    PENDING = "pending"
    ACTIVE = "active"
    DISABLED = "disabled"
    ERROR = "error"


def _profile_state_type() -> Enum:
    return Enum(
        ProfileState,
        values_callable=lambda members: [member.value for member in members],
        name="profile_state",
        native_enum=False,
        create_constraint=False,
        validate_strings=True,
    )


class Admin(Base):
    __tablename__ = "admins"
    __table_args__ = (
        UniqueConstraint("login", name="uq_admins_login"),
        UniqueConstraint("singleton_key", name="uq_admins_singleton_key"),
        CheckConstraint("length(login) BETWEEN 1 AND 128", name="ck_admins_login_length"),
        CheckConstraint("session_version >= 1", name="ck_admins_session_version"),
        CheckConstraint("singleton_key = 1", name="ck_admins_singleton_key"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    login: Mapped[str] = mapped_column(String(128), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    singleton_key: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    session_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), nullable=False, server_default=func.current_timestamp()
    )
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), nullable=False, server_default=func.current_timestamp()
    )
    last_login_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)


class AdminSession(Base):
    __tablename__ = "admin_sessions"
    __table_args__ = (
        UniqueConstraint("token_digest", name="uq_admin_sessions_token_digest"),
        CheckConstraint("session_version >= 1", name="ck_admin_sessions_version"),
        Index("ix_admin_sessions_admin_id", "admin_id"),
        Index("ix_admin_sessions_absolute_expiry", "absolute_expires_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    admin_id: Mapped[str] = mapped_column(
        ForeignKey("admins.id", ondelete="CASCADE"), nullable=False
    )
    token_digest: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    csrf_digest: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    session_version: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    idle_expires_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    absolute_expires_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)


class LoginThrottle(Base):
    __tablename__ = "login_throttles"
    __table_args__ = (
        UniqueConstraint("scope", "key_digest", name="uq_login_throttles_scope_key"),
        CheckConstraint("scope IN ('ip', 'login')", name="ck_login_throttles_scope"),
        CheckConstraint("failure_count >= 0", name="ck_login_throttles_failure_count"),
        Index("ix_login_throttles_blocked_until", "blocked_until"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scope: Mapped[str] = mapped_column(String(16), nullable=False)
    key_digest: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    failure_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    window_started_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    last_failed_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    blocked_until: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)


class Profile(Base):
    __tablename__ = "profiles"
    __table_args__ = (
        UniqueConstraint("runtime_id", name="uq_profiles_runtime_id"),
        CheckConstraint(
            "state IN ('pending', 'active', 'disabled', 'error')",
            name="ck_profiles_state",
        ),
        CheckConstraint("length(name) BETWEEN 1 AND 64", name="ck_profiles_name_length"),
        CheckConstraint("length(runtime_id) = 28", name="ck_profiles_runtime_id_length"),
        Index("ix_profiles_state", "state"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[ProfileState] = mapped_column(_profile_state_type(), nullable=False)
    runtime_id: Mapped[str] = mapped_column(String(28), nullable=False)
    wrapped_profile_key: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    user_id_ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    hysteria_secret_ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    subscription_token_ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    last_error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), nullable=False, server_default=func.current_timestamp()
    )
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), nullable=False, server_default=func.current_timestamp()
    )
    disabled_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)


class ProfileLookup(Base):
    __tablename__ = "profile_lookups"
    __table_args__ = (
        UniqueConstraint("lookup_digest", name="uq_profile_lookups_digest"),
        UniqueConstraint("profile_id", "kind", name="uq_profile_lookups_profile_kind"),
        CheckConstraint("length(lookup_digest) = 32", name="ck_profile_lookups_digest_length"),
        Index("ix_profile_lookups_profile_id", "profile_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    profile_id: Mapped[str] = mapped_column(
        ForeignKey("profiles.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    lookup_digest: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), nullable=False, server_default=func.current_timestamp()
    )


class SystemState(Base):
    __tablename__ = "system_state"
    __table_args__ = (
        CheckConstraint("length(key) BETWEEN 1 AND 128", name="ck_system_state_key_length"),
    )

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value_json: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), nullable=False, server_default=func.current_timestamp()
    )


class AuditEvent(Base):
    __tablename__ = "audit_events"
    __table_args__ = (
        CheckConstraint(
            "length(event_type) BETWEEN 1 AND 64", name="ck_audit_events_type_length"
        ),
        Index("ix_audit_events_occurred_at", "occurred_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_admin_id: Mapped[str | None] = mapped_column(
        ForeignKey("admins.id", ondelete="SET NULL"), nullable=True
    )
    subject_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    details_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    occurred_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), nullable=False, server_default=func.current_timestamp()
    )
