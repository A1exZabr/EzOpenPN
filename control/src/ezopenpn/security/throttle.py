from __future__ import annotations

import hmac
import unicodedata
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from uuid import uuid4

from sqlalchemy import Engine, and_, delete, or_, select, text

from ezopenpn.db import session_scope
from ezopenpn.models import LoginThrottle

_IP_LABEL = b"ezopenpn/login-throttle-ip/v1"
_LOGIN_LABEL = b"ezopenpn/login-throttle-login/v1"
_DECAY_WINDOW = timedelta(minutes=15)
_MAX_DELAY_SECONDS = 30


def _derive_key(master_key: bytes, label: bytes) -> bytes:
    if len(master_key) != 32:
        raise ValueError("master key must contain exactly 32 bytes")
    return hmac.digest(master_key, label, "sha256")


def _timestamp(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("time must include a timezone")
    return value.astimezone(UTC)


class LoginThrottleService:
    def __init__(self, engine: Engine, master_key: bytes) -> None:
        self._engine = engine
        self._ip_key = _derive_key(master_key, _IP_LABEL)
        self._login_key = _derive_key(master_key, _LOGIN_LABEL)

    def _identities(self, ip: str, login: str) -> tuple[tuple[str, bytes], tuple[str, bytes]]:
        direct_peer = ip.strip()
        try:
            normalized_ip = ip_address(direct_peer).compressed.encode("ascii")
        except ValueError:
            normalized_ip = ("peer:" + direct_peer[:255].casefold()).encode("utf-8")
        normalized_login = unicodedata.normalize("NFKC", login[:1024]).strip().casefold()
        normalized_login_bytes = normalized_login.encode("utf-8")
        return (
            ("ip", hmac.digest(self._ip_key, normalized_ip, "sha256")),
            ("login", hmac.digest(self._login_key, normalized_login_bytes, "sha256")),
        )

    def register_failure(self, ip: str, login: str, now: datetime) -> timedelta:
        timestamp = _timestamp(now)
        longest_delay = 0
        with session_scope(self._engine) as session:
            session.execute(text("BEGIN IMMEDIATE"))
            for scope, digest in self._identities(ip, login):
                stored = session.scalar(
                    select(LoginThrottle).where(
                        LoginThrottle.scope == scope,
                        LoginThrottle.key_digest == digest,
                    )
                )
                if stored is None:
                    stored = LoginThrottle(
                        id=str(uuid4()),
                        scope=scope,
                        key_digest=digest,
                        failure_count=0,
                        window_started_at=timestamp,
                        last_failed_at=timestamp,
                    )
                    session.add(stored)
                if timestamp - stored.last_failed_at > _DECAY_WINDOW:
                    stored.failure_count = 0
                    stored.window_started_at = timestamp
                stored.failure_count += 1
                stored.last_failed_at = timestamp
                delay_seconds = min(
                    _MAX_DELAY_SECONDS, 2 ** (stored.failure_count - 1)
                )
                stored.blocked_until = timestamp + timedelta(seconds=delay_seconds)
                longest_delay = max(longest_delay, delay_seconds)
        return timedelta(seconds=longest_delay)

    def retry_after(self, ip: str, login: str, now: datetime) -> timedelta:
        timestamp = _timestamp(now)
        (ip_scope, ip_digest), (login_scope, login_digest) = self._identities(ip, login)
        with session_scope(self._engine) as session:
            rows = session.scalars(
                select(LoginThrottle).where(
                    or_(
                        and_(
                            LoginThrottle.scope == ip_scope,
                            LoginThrottle.key_digest == ip_digest,
                        ),
                        and_(
                            LoginThrottle.scope == login_scope,
                            LoginThrottle.key_digest == login_digest,
                        ),
                    )
                )
            ).all()
            remaining = [
                row.blocked_until - timestamp
                for row in rows
                if row.blocked_until is not None and row.blocked_until > timestamp
            ]
            return max(remaining, default=timedelta())

    def clear(self, ip: str, login: str) -> None:
        (ip_scope, ip_digest), (login_scope, login_digest) = self._identities(ip, login)
        with session_scope(self._engine) as session:
            session.execute(text("BEGIN IMMEDIATE"))
            session.execute(
                delete(LoginThrottle).where(
                    or_(
                        and_(
                            LoginThrottle.scope == ip_scope,
                            LoginThrottle.key_digest == ip_digest,
                        ),
                        and_(
                            LoginThrottle.scope == login_scope,
                            LoginThrottle.key_digest == login_digest,
                        ),
                    )
                )
            )
