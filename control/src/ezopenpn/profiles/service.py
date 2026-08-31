from __future__ import annotations

import base64
import unicodedata
from collections.abc import Callable
from secrets import token_bytes
from uuid import UUID, uuid4

from ezopenpn.models import ProfileState
from ezopenpn.profiles.repository import ProfileRepository
from ezopenpn.profiles.types import (
    NewProfileMaterial,
    ProfileRecord,
    ProfileResult,
    hysteria_lookup_value,
    profile_value_context,
)
from ezopenpn.security.secrets import SecretCipher


class InvalidProfileName(ValueError):
    pass


def _normalize_name(name: str) -> str:
    normalized = name.strip()
    if not 1 <= len(normalized) <= 64:
        raise InvalidProfileName("profile name must contain between 1 and 64 characters")
    if any(unicodedata.category(character).startswith("C") for character in normalized):
        raise InvalidProfileName("profile name must not contain control characters")
    return normalized


def _random_exact(random_bytes: Callable[[int], bytes], size: int) -> bytes:
    value = random_bytes(size)
    if len(value) != size:
        raise ValueError("random provider returned an invalid byte count")
    return value


def _url_token(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _runtime_id(value: bytes) -> str:
    encoded = base64.b32encode(value).rstrip(b"=").decode("ascii").lower()
    return "p_" + encoded[:26]


def _result(record: ProfileRecord, subscription_token: str | None = None) -> ProfileResult:
    return ProfileResult(
        profile_id=record.profile_id,
        name=record.name,
        state=record.state,
        runtime_id=record.runtime_id,
        subscription_token=subscription_token,
    )


class ProfileService:
    def __init__(
        self,
        repository: ProfileRepository,
        cipher: SecretCipher,
        random_bytes: Callable[[int], bytes] = token_bytes,
        uuid_factory: Callable[[], UUID] = uuid4,
    ) -> None:
        self.repository = repository
        self._cipher = cipher
        self._random_bytes = random_bytes
        self._uuid_factory = uuid_factory

    def create(self, name: str) -> ProfileResult:
        normalized_name = _normalize_name(name)
        profile_id = self._uuid_factory()
        user_id = self._uuid_factory()
        hysteria_secret = _random_exact(self._random_bytes, 32)
        subscription_token = _url_token(_random_exact(self._random_bytes, 32))
        hysteria_auth = _url_token(hysteria_secret)
        runtime_id = _runtime_id(_random_exact(self._random_bytes, 17))
        profile_key = self._cipher.new_profile_key()
        material = NewProfileMaterial(
            profile_id=profile_id,
            name=normalized_name,
            runtime_id=runtime_id,
            wrapped_profile_key=self._cipher.wrap_profile_key(profile_id, profile_key),
            user_id_ciphertext=self._cipher.encrypt_profile_value(
                profile_key,
                user_id.bytes,
                profile_value_context(profile_id, "user-id"),
            ),
            hysteria_secret_ciphertext=self._cipher.encrypt_profile_value(
                profile_key,
                hysteria_secret,
                profile_value_context(profile_id, "hysteria-auth"),
            ),
            subscription_token_ciphertext=self._cipher.encrypt_profile_value(
                profile_key,
                subscription_token.encode("ascii"),
                profile_value_context(profile_id, "subscription-token"),
            ),
            subscription_lookup_digest=self._cipher.lookup_digest(
                subscription_token.encode("ascii")
            ),
            hysteria_lookup_digest=self._cipher.lookup_digest(
                hysteria_lookup_value(hysteria_auth)
            ),
        )
        return _result(self.repository.insert_pending(material), subscription_token)

    def disable_local(self, profile_id: UUID) -> ProfileResult:
        return _result(self.repository.set_state(profile_id, ProfileState.DISABLED))

    def enable_local(self, profile_id: UUID) -> ProfileResult:
        return _result(self.repository.set_state(profile_id, ProfileState.ACTIVE))

    def mark_active(self, profile_id: UUID) -> ProfileResult:
        return _result(self.repository.set_state(profile_id, ProfileState.ACTIVE))

    def mark_error(self, profile_id: UUID, error_code: str) -> ProfileResult:
        return _result(
            self.repository.set_state(profile_id, ProfileState.ERROR, error_code=error_code)
        )
