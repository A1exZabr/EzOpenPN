from __future__ import annotations

from dataclasses import dataclass

from argon2 import PasswordHasher as Argon2Hasher
from argon2.exceptions import InvalidHashError, VerificationError
from argon2.low_level import Type


@dataclass(frozen=True, slots=True)
class PasswordCheck:
    valid: bool
    needs_rehash: bool = False


class PasswordHasher:
    __slots__ = ("_hasher",)

    def __init__(self) -> None:
        self._hasher = Argon2Hasher(
            time_cost=3,
            memory_cost=65536,
            parallelism=2,
            hash_len=32,
            salt_len=16,
            type=Type.ID,
        )

    def hash(self, password: str) -> str:
        return self._hasher.hash(password)

    def verify(self, encoded: str, password: str) -> PasswordCheck:
        try:
            valid = self._hasher.verify(encoded, password)
        except (VerificationError, InvalidHashError):
            return PasswordCheck(valid=False)
        if not valid:
            return PasswordCheck(valid=False)
        return PasswordCheck(valid=True, needs_rehash=self._hasher.check_needs_rehash(encoded))
