from __future__ import annotations

import base64
import hmac
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from secrets import token_bytes

from sqlalchemy import Engine, delete, select, text

from ezopenpn.db import session_scope
from ezopenpn.models import SystemState

_FORM_LABEL = b"ezopenpn/preauth-form/v1"
_STORE_LABEL = b"ezopenpn/preauth-store/v1"
_STATE_PREFIX = "preauth:"
_TOKEN_BYTES = 32
_MAX_TOKEN_TEXT = 128


def _default_clock() -> datetime:
    return datetime.now(UTC)


def _derive(master_key: bytes, label: bytes) -> bytes:
    if len(master_key) != 32:
        raise ValueError("master key must contain exactly 32 bytes")
    return hmac.digest(master_key, label, "sha256")


def _token(random_bytes: Callable[[int], bytes]) -> str:
    value = random_bytes(_TOKEN_BYTES)
    if len(value) != _TOKEN_BYTES:
        raise ValueError("random provider returned an invalid byte count")
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("time must include a timezone")
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class PreAuthChallenge:
    cookie_nonce: str = field(repr=False)
    form_token: str = field(repr=False)
    expires_at: datetime


class PreAuthService:
    def __init__(
        self,
        engine: Engine,
        master_key: bytes,
        lifetime: timedelta = timedelta(minutes=5),
        clock: Callable[[], datetime] = _default_clock,
        random_bytes: Callable[[int], bytes] = token_bytes,
    ) -> None:
        if lifetime <= timedelta():
            raise ValueError("challenge lifetime must be positive")
        self._engine = engine
        self._form_key = _derive(master_key, _FORM_LABEL)
        self._store_key = _derive(master_key, _STORE_LABEL)
        self._lifetime = lifetime
        self._clock = clock
        self._random_bytes = random_bytes

    def _form_token(self, nonce: str) -> str:
        digest = hmac.digest(self._form_key, nonce.encode("ascii"), "sha256")
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

    def _state_key(self, nonce: str) -> str:
        digest = hmac.digest(self._store_key, nonce.encode("ascii"), "sha256")
        return _STATE_PREFIX + digest.hex()

    def issue(self) -> PreAuthChallenge:
        timestamp = _utc(self._clock())
        expires_at = timestamp + self._lifetime
        nonce = _token(self._random_bytes)
        state = SystemState(
            key=self._state_key(nonce),
            value_json=json.dumps(
                {"expires_at": expires_at.isoformat()}, separators=(",", ":")
            ),
            updated_at=timestamp,
        )
        with session_scope(self._engine) as session:
            session.execute(text("BEGIN IMMEDIATE"))
            session.execute(
                delete(SystemState).where(
                    SystemState.key.like(f"{_STATE_PREFIX}%"),
                    SystemState.updated_at < timestamp - self._lifetime,
                )
            )
            session.add(state)
        return PreAuthChallenge(
            cookie_nonce=nonce,
            form_token=self._form_token(nonce),
            expires_at=expires_at,
        )

    def consume(self, cookie_nonce: str, form_token: str) -> bool:
        if (
            not 1 <= len(cookie_nonce) <= _MAX_TOKEN_TEXT
            or not 1 <= len(form_token) <= _MAX_TOKEN_TEXT
            or not cookie_nonce.isascii()
            or not form_token.isascii()
        ):
            return False
        expected = self._form_token(cookie_nonce)
        if not hmac.compare_digest(expected, form_token):
            return False
        timestamp = _utc(self._clock())
        with session_scope(self._engine) as session:
            session.execute(text("BEGIN IMMEDIATE"))
            state = session.scalar(
                select(SystemState).where(SystemState.key == self._state_key(cookie_nonce))
            )
            if state is None:
                return False
            session.delete(state)
            try:
                expires_at = datetime.fromisoformat(
                    str(json.loads(state.value_json)["expires_at"])
                )
            except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                return False
            return _utc(expires_at) > timestamp
