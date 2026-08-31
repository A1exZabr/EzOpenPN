from __future__ import annotations

import unicodedata
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import Engine, select, update
from sqlalchemy.exc import IntegrityError

from ezopenpn.db import session_scope
from ezopenpn.models import Admin, AdminSession
from ezopenpn.security.passwords import PasswordHasher

_DUMMY_HASH = PasswordHasher().hash("fixed non-secret verification phrase")


class AdminAlreadyExists(RuntimeError):
    pass


class AdminNotInitialized(RuntimeError):
    pass


class InvalidAdminInput(ValueError):
    pass


def normalize_login(login: str) -> str:
    normalized = unicodedata.normalize("NFKC", login).strip().casefold()
    if not 1 <= len(normalized) <= 64:
        raise InvalidAdminInput("login must contain between 1 and 64 characters")
    if any(unicodedata.category(character).startswith("C") for character in normalized):
        raise InvalidAdminInput("login must not contain control characters")
    return normalized


def validate_new_password(value: str, normalized_login: str | None = None) -> None:
    if not 12 <= len(value) <= 1024:
        raise InvalidAdminInput("password must contain between 12 and 1024 characters")
    if any(unicodedata.category(character).startswith("C") for character in value):
        raise InvalidAdminInput("password must not contain control characters")
    if normalized_login is not None and value == normalized_login:
        raise InvalidAdminInput("password must differ from login")


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("time must include a timezone")
    return value.astimezone(UTC)


class AdminService:
    def __init__(self, engine: Engine, hasher: PasswordHasher | None = None) -> None:
        self._engine = engine
        self._hasher = hasher or PasswordHasher()

    def create_initial(self, login: str, password: str) -> Admin:
        normalized_login = normalize_login(login)
        validate_new_password(password, normalized_login)
        administrator = Admin(
            id=str(uuid4()),
            login=normalized_login,
            password_hash=self._hasher.hash(password),
            singleton_key=1,
            session_version=1,
        )
        try:
            with session_scope(self._engine) as session:
                session.add(administrator)
                session.flush()
                session.expunge(administrator)
        except IntegrityError as error:
            raise AdminAlreadyExists("administrator is already initialized") from error
        return administrator

    def verify_credentials(self, login: str, password: str, now: datetime) -> Admin | None:
        timestamp = _utc(now)
        try:
            normalized_login = normalize_login(login)
        except InvalidAdminInput:
            self._hasher.verify(_DUMMY_HASH, password)
            return None

        with session_scope(self._engine) as session:
            administrator = session.scalar(select(Admin).where(Admin.login == normalized_login))
            if administrator is None:
                self._hasher.verify(_DUMMY_HASH, password)
                return None

            check = self._hasher.verify(administrator.password_hash, password)
            if not check.valid:
                return None
            if check.needs_rehash:
                administrator.password_hash = self._hasher.hash(password)
            administrator.last_login_at = timestamp
            administrator.updated_at = timestamp
            session.flush()
            session.expunge(administrator)
            return administrator

    def reset_password(self, password: str, now: datetime | None = None) -> None:
        timestamp = _utc(now or datetime.now(UTC))
        with session_scope(self._engine) as session:
            administrator = session.scalar(select(Admin))
            if administrator is None:
                raise AdminNotInitialized("administrator is not initialized")
            validate_new_password(password, administrator.login)
            administrator.password_hash = self._hasher.hash(password)
            administrator.session_version += 1
            administrator.updated_at = timestamp
            session.execute(
                update(AdminSession)
                .where(
                    AdminSession.admin_id == administrator.id,
                    AdminSession.revoked_at.is_(None),
                )
                .values(revoked_at=timestamp)
            )
