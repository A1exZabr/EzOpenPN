from __future__ import annotations

import hmac
from collections.abc import Callable
from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import Engine, delete, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import aliased

from ezopenpn.db import session_scope
from ezopenpn.models import Profile, ProfileLookup, ProfileState
from ezopenpn.profiles.types import (
    NewProfileMaterial,
    ProfileRecord,
    hysteria_lookup_value,
)
from ezopenpn.security.secrets import SecretCipher

_SUBSCRIPTION_LOOKUP_KIND = "subscription"
_HYSTERIA_LOOKUP_KIND = "hysteria-auth"
_LEGAL_TRANSITIONS = {
    ProfileState.PENDING: frozenset({ProfileState.ACTIVE, ProfileState.ERROR}),
    ProfileState.ERROR: frozenset({ProfileState.PENDING, ProfileState.DISABLED}),
    ProfileState.ACTIVE: frozenset({ProfileState.DISABLED, ProfileState.ERROR}),
    ProfileState.DISABLED: frozenset({ProfileState.ACTIVE, ProfileState.ERROR}),
}


class ProfileNotFound(LookupError):
    pass


class ProfileConflict(RuntimeError):
    pass


class InvalidProfileTransition(RuntimeError):
    pass


def _default_clock() -> datetime:
    return datetime.now(UTC)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("profile clock must include a timezone")
    return value.astimezone(UTC)


def _record(profile: Profile, lookup_digest: bytes) -> ProfileRecord:
    return ProfileRecord(
        profile_id=UUID(profile.id),
        name=profile.name,
        state=profile.state,
        runtime_id=profile.runtime_id,
        wrapped_profile_key=profile.wrapped_profile_key,
        user_id_ciphertext=profile.user_id_ciphertext,
        hysteria_secret_ciphertext=profile.hysteria_secret_ciphertext,
        subscription_token_ciphertext=profile.subscription_token_ciphertext,
        subscription_lookup_digest=lookup_digest,
        created_at=profile.created_at,
        updated_at=profile.updated_at,
        disabled_at=profile.disabled_at,
        last_error_code=profile.last_error_code,
    )


class ProfileRepository:
    def __init__(
        self,
        engine: Engine,
        cipher: SecretCipher,
        clock: Callable[[], datetime] = _default_clock,
    ) -> None:
        self._engine = engine
        self._cipher = cipher
        self._clock = clock

    def insert_pending(self, material: NewProfileMaterial) -> ProfileRecord:
        profile = Profile(
            id=str(material.profile_id),
            name=material.name,
            state=ProfileState.PENDING,
            runtime_id=material.runtime_id,
            wrapped_profile_key=material.wrapped_profile_key,
            user_id_ciphertext=material.user_id_ciphertext,
            hysteria_secret_ciphertext=material.hysteria_secret_ciphertext,
            subscription_token_ciphertext=material.subscription_token_ciphertext,
        )
        subscription_lookup = ProfileLookup(
            id=str(uuid4()),
            profile_id=profile.id,
            kind=_SUBSCRIPTION_LOOKUP_KIND,
            lookup_digest=material.subscription_lookup_digest,
        )
        hysteria_lookup = ProfileLookup(
            id=str(uuid4()),
            profile_id=profile.id,
            kind=_HYSTERIA_LOOKUP_KIND,
            lookup_digest=material.hysteria_lookup_digest,
        )
        try:
            with session_scope(self._engine) as session:
                session.add_all((profile, subscription_lookup, hysteria_lookup))
                session.flush()
                return _record(profile, subscription_lookup.lookup_digest)
        except IntegrityError as error:
            raise ProfileConflict("profile identifiers conflict") from error

    def get(self, profile_id: UUID) -> ProfileRecord:
        with session_scope(self._engine) as session:
            row = session.execute(
                select(Profile, ProfileLookup.lookup_digest)
                .join(ProfileLookup, ProfileLookup.profile_id == Profile.id)
                .where(
                    Profile.id == str(profile_id),
                    ProfileLookup.kind == _SUBSCRIPTION_LOOKUP_KIND,
                )
            ).one_or_none()
            if row is None:
                raise ProfileNotFound("profile is unavailable")
            return _record(row[0], row[1])

    def list(self) -> tuple[ProfileRecord, ...]:
        with session_scope(self._engine) as session:
            rows = session.execute(
                select(Profile, ProfileLookup.lookup_digest)
                .join(ProfileLookup, ProfileLookup.profile_id == Profile.id)
                .where(ProfileLookup.kind == _SUBSCRIPTION_LOOKUP_KIND)
                .order_by(Profile.created_at, Profile.id)
            ).all()
            return tuple(_record(profile, digest) for profile, digest in rows)

    def find_by_subscription_token(self, token: str) -> ProfileRecord | None:
        if not 1 <= len(token) <= 128 or not token.isascii():
            return None
        digest = self._cipher.lookup_digest(token.encode("ascii"))
        with session_scope(self._engine) as session:
            row = session.execute(
                select(Profile, ProfileLookup.lookup_digest)
                .join(ProfileLookup, ProfileLookup.profile_id == Profile.id)
                .where(
                    ProfileLookup.kind == _SUBSCRIPTION_LOOKUP_KIND,
                    ProfileLookup.lookup_digest == digest,
                )
            ).one_or_none()
            if row is None or not hmac.compare_digest(row[1], digest):
                return None
            return _record(row[0], row[1])

    def find_by_hysteria_secret(self, presented: str) -> ProfileRecord | None:
        if not 1 <= len(presented) <= 512 or not presented.isascii():
            return None
        digest = self._cipher.lookup_digest(hysteria_lookup_value(presented))
        auth_lookup = aliased(ProfileLookup)
        subscription_lookup = aliased(ProfileLookup)
        with session_scope(self._engine) as session:
            row = session.execute(
                select(
                    Profile,
                    auth_lookup.lookup_digest,
                    subscription_lookup.lookup_digest,
                )
                .join(auth_lookup, auth_lookup.profile_id == Profile.id)
                .join(subscription_lookup, subscription_lookup.profile_id == Profile.id)
                .where(
                    auth_lookup.kind == _HYSTERIA_LOOKUP_KIND,
                    auth_lookup.lookup_digest == digest,
                    subscription_lookup.kind == _SUBSCRIPTION_LOOKUP_KIND,
                )
            ).one_or_none()
            if row is None or not hmac.compare_digest(row[1], digest):
                return None
            return _record(row[0], row[2])

    def set_state(
        self,
        profile_id: UUID,
        state: ProfileState,
        error_code: str | None = None,
    ) -> ProfileRecord:
        timestamp = _utc(self._clock())
        with session_scope(self._engine) as session:
            session.execute(text("BEGIN IMMEDIATE"))
            row = session.execute(
                select(Profile, ProfileLookup.lookup_digest)
                .join(ProfileLookup, ProfileLookup.profile_id == Profile.id)
                .where(
                    Profile.id == str(profile_id),
                    ProfileLookup.kind == _SUBSCRIPTION_LOOKUP_KIND,
                )
            ).one_or_none()
            if row is None:
                raise ProfileNotFound("profile is unavailable")
            profile, digest = row
            if profile.state is not state:
                if state not in _LEGAL_TRANSITIONS[profile.state]:
                    raise InvalidProfileTransition("profile state transition is invalid")
                profile.state = state
            profile.updated_at = timestamp
            profile.last_error_code = error_code if state is ProfileState.ERROR else None
            profile.disabled_at = timestamp if state is ProfileState.DISABLED else None
            session.flush()
            return _record(profile, digest)

    def delete_local(self, profile_id: UUID) -> None:
        with session_scope(self._engine) as session:
            session.execute(text("BEGIN IMMEDIATE"))
            profile = session.get(Profile, str(profile_id))
            if profile is None:
                raise ProfileNotFound("profile is unavailable")
            profile.wrapped_profile_key = None
            session.flush()
            session.execute(
                delete(ProfileLookup).where(ProfileLookup.profile_id == profile.id)
            )
            session.delete(profile)
