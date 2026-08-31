from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID

from ezopenpn.models import ProfileState


def profile_value_context(profile_id: UUID, field_name: str) -> bytes:
    return f"ezopenpn/profile/{profile_id}/{field_name}/v1".encode("ascii")


@dataclass(frozen=True, slots=True)
class NewProfileMaterial:
    profile_id: UUID
    name: str
    runtime_id: str
    wrapped_profile_key: bytes = field(repr=False)
    user_id_ciphertext: bytes = field(repr=False)
    hysteria_secret_ciphertext: bytes = field(repr=False)
    subscription_token_ciphertext: bytes = field(repr=False)
    subscription_lookup_digest: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class ProfileRecord:
    profile_id: UUID
    name: str
    state: ProfileState
    runtime_id: str
    wrapped_profile_key: bytes | None = field(repr=False)
    user_id_ciphertext: bytes = field(repr=False)
    hysteria_secret_ciphertext: bytes = field(repr=False)
    subscription_token_ciphertext: bytes = field(repr=False)
    subscription_lookup_digest: bytes = field(repr=False)
    created_at: datetime
    updated_at: datetime
    disabled_at: datetime | None
    last_error_code: str | None


@dataclass(frozen=True, slots=True)
class LinkBundle:
    combined_url: str = field(repr=False)
    vless_link: str = field(repr=False)
    hysteria_link: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class ProfileResult:
    profile_id: UUID
    name: str
    state: ProfileState
    runtime_id: str
    subscription_token: str | None = field(default=None, repr=False)
    link_bundle: LinkBundle | None = field(default=None, repr=False)
