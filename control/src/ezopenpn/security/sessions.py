from __future__ import annotations

import base64
import hmac
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from secrets import token_bytes
from uuid import UUID, uuid4

from sqlalchemy import Engine, select

from ezopenpn.db import session_scope
from ezopenpn.models import Admin, AdminSession

_SESSION_LABEL = b"ezopenpn/session/v1"
_CSRF_LABEL = b"ezopenpn/csrf/v1"
_TOKEN_BYTES = 32
_MAX_TOKEN_TEXT = 128


class SessionAdminNotFound(RuntimeError):
    pass


def _derive_key(master_key: bytes, label: bytes) -> bytes:
    if len(master_key) != 32:
        raise ValueError("master key must contain exactly 32 bytes")
    return hmac.digest(master_key, label, "sha256")


def _token() -> str:
    return base64.urlsafe_b64encode(token_bytes(_TOKEN_BYTES)).rstrip(b"=").decode("ascii")


def _timestamp(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("time must include a timezone")
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class SessionGrant:
    session_id: UUID
    raw_token: str = field(repr=False)
    csrf_token: str = field(repr=False)
    idle_expires_at: datetime
    absolute_expires_at: datetime


@dataclass(frozen=True, slots=True)
class SessionIdentity:
    session_id: UUID
    admin_id: UUID
    login: str
    csrf_digest: bytes = field(repr=False)


class SessionService:
    def __init__(
        self,
        engine: Engine,
        master_key: bytes,
        idle_duration: timedelta = timedelta(hours=12),
        absolute_duration: timedelta = timedelta(days=7),
    ) -> None:
        if idle_duration <= timedelta() or absolute_duration <= timedelta():
            raise ValueError("session durations must be positive")
        if idle_duration > absolute_duration:
            raise ValueError("idle duration must not exceed absolute duration")
        self._engine = engine
        self._session_key = _derive_key(master_key, _SESSION_LABEL)
        self._csrf_key = _derive_key(master_key, _CSRF_LABEL)
        self._idle_duration = idle_duration
        self._absolute_duration = absolute_duration

    def _session_digest(self, raw_token: str) -> bytes:
        return hmac.digest(self._session_key, raw_token.encode("ascii"), "sha256")

    def _csrf_digest(self, raw_token: str) -> bytes:
        return hmac.digest(self._csrf_key, raw_token.encode("ascii"), "sha256")

    def create(self, admin_id: UUID, now: datetime) -> SessionGrant:
        timestamp = _timestamp(now)
        raw_token = _token()
        csrf_token = _token()
        session_id = uuid4()
        absolute_expires_at = timestamp + self._absolute_duration
        idle_expires_at = min(timestamp + self._idle_duration, absolute_expires_at)
        with session_scope(self._engine) as session:
            administrator = session.get(Admin, str(admin_id))
            if administrator is None:
                raise SessionAdminNotFound("administrator is unavailable")
            session.add(
                AdminSession(
                    id=str(session_id),
                    admin_id=administrator.id,
                    token_digest=self._session_digest(raw_token),
                    csrf_digest=self._csrf_digest(csrf_token),
                    session_version=administrator.session_version,
                    created_at=timestamp,
                    last_seen_at=timestamp,
                    idle_expires_at=idle_expires_at,
                    absolute_expires_at=absolute_expires_at,
                )
            )
        return SessionGrant(
            session_id=session_id,
            raw_token=raw_token,
            csrf_token=csrf_token,
            idle_expires_at=idle_expires_at,
            absolute_expires_at=absolute_expires_at,
        )

    def authenticate(self, raw_token: str, now: datetime) -> SessionIdentity | None:
        timestamp = _timestamp(now)
        if not 1 <= len(raw_token) <= _MAX_TOKEN_TEXT or not raw_token.isascii():
            return None
        digest = self._session_digest(raw_token)
        with session_scope(self._engine) as session:
            stored = session.scalar(
                select(AdminSession).where(AdminSession.token_digest == digest)
            )
            if stored is None or not hmac.compare_digest(stored.token_digest, digest):
                return None
            administrator = session.get(Admin, stored.admin_id)
            if administrator is None:
                if stored.revoked_at is None:
                    stored.revoked_at = timestamp
                return None
            expired = (
                stored.revoked_at is not None
                or stored.idle_expires_at <= timestamp
                or stored.absolute_expires_at <= timestamp
                or stored.session_version != administrator.session_version
            )
            if expired:
                if stored.revoked_at is None:
                    stored.revoked_at = timestamp
                return None

            stored.last_seen_at = timestamp
            stored.idle_expires_at = min(
                timestamp + self._idle_duration, stored.absolute_expires_at
            )
            return SessionIdentity(
                session_id=UUID(stored.id),
                admin_id=UUID(administrator.id),
                login=administrator.login,
                csrf_digest=stored.csrf_digest,
            )

    def validate_csrf(self, identity: SessionIdentity, raw_token: str) -> bool:
        if not 1 <= len(raw_token) <= _MAX_TOKEN_TEXT or not raw_token.isascii():
            return False
        return hmac.compare_digest(identity.csrf_digest, self._csrf_digest(raw_token))

    def revoke(self, session_id: UUID, now: datetime) -> None:
        timestamp = _timestamp(now)
        with session_scope(self._engine) as session:
            stored = session.get(AdminSession, str(session_id))
            if stored is not None and stored.revoked_at is None:
                stored.revoked_at = timestamp
