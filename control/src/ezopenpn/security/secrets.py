from __future__ import annotations

import hmac
from uuid import UUID

from nacl.secret import Aead
from nacl.utils import random

_FORMAT_VERSION = b"\x01"
_WRAP_DERIVATION_LABEL = b"ezopenpn/wrap/v1"
_LOOKUP_DERIVATION_LABEL = b"ezopenpn/lookup/v1"
_PROFILE_KEY_CONTEXT = b"ezopenpn/profile-key/v1:"


def _require_key(key: bytes, label: str) -> None:
    if len(key) != Aead.KEY_SIZE:
        raise ValueError(f"{label} must contain exactly 32 bytes")


def _encrypt(key: bytes, value: bytes, context: bytes) -> bytes:
    _require_key(key, "encryption key")
    if not context:
        raise ValueError("encryption context must not be empty")
    return _FORMAT_VERSION + bytes(Aead(key).encrypt(value, context))


def _decrypt(key: bytes, blob: bytes, context: bytes) -> bytes:
    _require_key(key, "encryption key")
    if not context:
        raise ValueError("encryption context must not be empty")
    minimum_size = len(_FORMAT_VERSION) + Aead.NONCE_SIZE + Aead.MACBYTES
    if len(blob) < minimum_size:
        raise ValueError("ciphertext is too short")
    if blob[:1] != _FORMAT_VERSION:
        raise ValueError("ciphertext format is unsupported")
    return Aead(key).decrypt(blob[1:], context)


class SecretCipher:
    __slots__ = ("_lookup_key", "_wrap_key")

    def __init__(self, master_key: bytes) -> None:
        _require_key(master_key, "master key")
        self._wrap_key = hmac.digest(master_key, _WRAP_DERIVATION_LABEL, "sha256")
        self._lookup_key = hmac.digest(master_key, _LOOKUP_DERIVATION_LABEL, "sha256")

    def new_profile_key(self) -> bytes:
        return random(Aead.KEY_SIZE)

    def encrypt_profile_value(self, key: bytes, value: bytes, context: bytes) -> bytes:
        return _encrypt(key, value, context)

    def decrypt_profile_value(self, key: bytes, blob: bytes, context: bytes) -> bytes:
        return _decrypt(key, blob, context)

    def wrap_profile_key(self, profile_id: UUID, key: bytes) -> bytes:
        _require_key(key, "profile key")
        return _encrypt(self._wrap_key, key, _PROFILE_KEY_CONTEXT + profile_id.bytes)

    def unwrap_profile_key(self, profile_id: UUID, wrapped: bytes) -> bytes:
        key = _decrypt(self._wrap_key, wrapped, _PROFILE_KEY_CONTEXT + profile_id.bytes)
        _require_key(key, "profile key")
        return key

    def lookup_digest(self, value: bytes) -> bytes:
        return hmac.digest(self._lookup_key, value, "sha256")

    def matches_lookup_digest(self, value: bytes, expected: bytes) -> bool:
        return hmac.compare_digest(self.lookup_digest(value), expected)
