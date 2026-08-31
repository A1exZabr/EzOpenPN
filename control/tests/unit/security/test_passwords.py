from argon2 import PasswordHasher as Argon2Hasher
from argon2.low_level import Type

from ezopenpn.security.passwords import PasswordHasher


def test_password_parameters_are_embedded() -> None:
    encoded = PasswordHasher().hash("correct horse battery staple")

    assert encoded.startswith("$argon2id$")
    assert "m=65536,t=3,p=2" in encoded


def test_password_verification_has_one_result_shape() -> None:
    hasher = PasswordHasher()
    encoded = hasher.hash("correct horse battery staple")

    assert hasher.verify(encoded, "correct horse battery staple").valid is True
    assert hasher.verify(encoded, "wrong horse battery staple").valid is False
    assert hasher.verify("not-an-argon-hash", "correct horse battery staple").valid is False


def test_successful_check_reports_parameter_upgrade() -> None:
    weaker = Argon2Hasher(
        time_cost=1,
        memory_cost=8192,
        parallelism=1,
        hash_len=16,
        salt_len=8,
        type=Type.ID,
    ).hash("correct horse battery staple")

    result = PasswordHasher().verify(weaker, "correct horse battery staple")

    assert result.valid is True
    assert result.needs_rehash is True
