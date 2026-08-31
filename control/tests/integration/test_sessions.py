from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

from sqlalchemy import Engine, select

from ezopenpn.db import create_engine_for, session_scope, upgrade_database
from ezopenpn.models import AdminSession, LoginThrottle
from ezopenpn.security.admin import AdminService
from ezopenpn.security.sessions import SessionService
from ezopenpn.security.throttle import LoginThrottleService

MASTER_KEY = bytes(range(32))
NOW = datetime(2026, 8, 31, 10, 0, tzinfo=UTC)


def _services(tmp_path: Path) -> tuple[Engine, AdminService, SessionService]:
    database = tmp_path / "state.db"
    upgrade_database(database)
    engine = create_engine_for(database)
    return engine, AdminService(engine), SessionService(engine, MASTER_KEY)


def test_password_reset_revokes_existing_session(tmp_path: Path) -> None:
    _, admins, sessions = _services(tmp_path)
    admin = admins.create_initial("owner", "first strong password")
    grant = sessions.create(UUID(admin.id), NOW)

    admins.reset_password("second strong password", NOW + timedelta(minutes=1))

    assert sessions.authenticate(grant.raw_token, NOW + timedelta(minutes=2)) is None


def test_session_has_idle_and_absolute_expiry(tmp_path: Path) -> None:
    _, admins, sessions = _services(tmp_path)
    admin = admins.create_initial("owner", "first strong password")
    grant = sessions.create(UUID(admin.id), NOW)

    assert sessions.authenticate(grant.raw_token, NOW + timedelta(hours=11)) is not None
    assert sessions.authenticate(grant.raw_token, NOW + timedelta(hours=22)) is not None
    assert sessions.authenticate(grant.raw_token, NOW + timedelta(days=7, seconds=1)) is None


def test_idle_session_expires_without_activity(tmp_path: Path) -> None:
    _, admins, sessions = _services(tmp_path)
    admin = admins.create_initial("owner", "first strong password")
    grant = sessions.create(UUID(admin.id), NOW)

    identity = sessions.authenticate(grant.raw_token, NOW + timedelta(hours=12, seconds=1))

    assert identity is None


def test_session_tokens_are_not_stored_and_csrf_is_bound_to_session(tmp_path: Path) -> None:
    engine, admins, sessions = _services(tmp_path)
    admin = admins.create_initial("owner", "first strong password")
    grant = sessions.create(UUID(admin.id), NOW)
    identity = sessions.authenticate(grant.raw_token, NOW)

    assert identity is not None
    assert sessions.validate_csrf(identity, grant.csrf_token) is True
    assert sessions.validate_csrf(identity, "wrong-csrf-value") is False
    assert grant.raw_token not in repr(grant)
    assert grant.csrf_token not in repr(grant)
    with session_scope(engine) as session:
        stored = session.scalar(select(AdminSession))
        assert stored is not None
        assert grant.raw_token.encode() not in stored.token_digest
        assert grant.csrf_token.encode() not in stored.csrf_digest


def test_login_throttle_uses_independent_digests_and_bounded_delays(tmp_path: Path) -> None:
    database = tmp_path / "state.db"
    upgrade_database(database)
    engine = create_engine_for(database)
    throttle = LoginThrottleService(engine, MASTER_KEY)

    delays = [
        throttle.register_failure("203.0.113.7", "Owner", NOW).total_seconds()
        for _ in range(7)
    ]

    assert delays == [1, 2, 4, 8, 16, 30, 30]
    assert throttle.retry_after("203.0.113.7", "owner", NOW).total_seconds() == 30
    with session_scope(engine) as session:
        rows = session.scalars(select(LoginThrottle)).all()
        assert {row.scope for row in rows} == {"ip", "login"}
        assert all(row.key_digest not in {b"203.0.113.7", b"owner"} for row in rows)


def test_login_throttle_decays_after_fifteen_minutes(tmp_path: Path) -> None:
    database = tmp_path / "state.db"
    upgrade_database(database)
    engine = create_engine_for(database)
    throttle = LoginThrottleService(engine, MASTER_KEY)
    throttle.register_failure("203.0.113.7", "owner", NOW)
    later = NOW + timedelta(minutes=15, seconds=1)

    delay = throttle.register_failure("203.0.113.7", "owner", later)

    assert delay == timedelta(seconds=1)


def test_login_throttle_counts_an_invalid_login_shape(tmp_path: Path) -> None:
    database = tmp_path / "state.db"
    upgrade_database(database)
    engine = create_engine_for(database)
    throttle = LoginThrottleService(engine, MASTER_KEY)

    delay = throttle.register_failure("203.0.113.7", "", NOW)

    assert delay == timedelta(seconds=1)
