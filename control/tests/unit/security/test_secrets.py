from uuid import UUID

import pytest
from nacl.exceptions import CryptoError

from ezopenpn.security.secrets import SecretCipher


def test_cipher_uses_distinct_nonces() -> None:
    cipher = SecretCipher(bytes(range(32)))
    profile_key = cipher.new_profile_key()
    first = cipher.encrypt_profile_value(profile_key, b"same", b"profile:one")
    second = cipher.encrypt_profile_value(profile_key, b"same", b"profile:one")

    assert first != second
    assert cipher.decrypt_profile_value(profile_key, first, b"profile:one") == b"same"


def test_ciphertext_is_bound_to_context() -> None:
    cipher = SecretCipher(bytes(range(32)))
    profile_key = cipher.new_profile_key()
    encrypted = cipher.encrypt_profile_value(profile_key, b"material", b"profile:one")

    with pytest.raises(CryptoError):
        cipher.decrypt_profile_value(profile_key, encrypted, b"profile:two")


def test_profile_key_wrap_is_bound_to_profile_id() -> None:
    cipher = SecretCipher(bytes(range(32)))
    profile_key = bytes(reversed(range(32)))
    profile_id = UUID("11111111-1111-4111-8111-111111111111")
    other_id = UUID("22222222-2222-4222-8222-222222222222")

    wrapped = cipher.wrap_profile_key(profile_id, profile_key)

    assert profile_key not in wrapped
    assert cipher.unwrap_profile_key(profile_id, wrapped) == profile_key
    with pytest.raises(CryptoError):
        cipher.unwrap_profile_key(other_id, wrapped)


def test_lookup_digest_is_deterministic_and_constant_time_comparable() -> None:
    cipher = SecretCipher(bytes(range(32)))
    first = cipher.lookup_digest(b"presented-value")

    assert len(first) == 32
    assert first == cipher.lookup_digest(b"presented-value")
    assert first != cipher.lookup_digest(b"different-value")
    assert cipher.matches_lookup_digest(b"presented-value", first) is True
    assert cipher.matches_lookup_digest(b"different-value", first) is False


def test_master_key_must_be_exactly_32_bytes() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        SecretCipher(b"short")
