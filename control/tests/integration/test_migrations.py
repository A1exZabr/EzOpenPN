from datetime import UTC
from pathlib import Path

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError

from ezopenpn.db import (
    create_engine_for,
    downgrade_database,
    session_scope,
    upgrade_database,
)
from ezopenpn.models import Admin, Base, Profile, ProfileLookup, ProfileState, SystemState

EXPECTED_TABLES = {
    "admins",
    "admin_sessions",
    "login_throttles",
    "profiles",
    "profile_lookups",
    "system_state",
    "audit_events",
    "alembic_version",
}


def test_initial_migration_creates_expected_tables(tmp_path: Path) -> None:
    database = tmp_path / "state.db"

    upgrade_database(database)

    inspector = inspect(create_engine(f"sqlite:///{database}"))
    assert set(inspector.get_table_names()) == EXPECTED_TABLES


def test_initial_migration_downgrades_back_to_empty(tmp_path: Path) -> None:
    database = tmp_path / "state.db"
    upgrade_database(database)

    downgrade_database(database)

    inspector = inspect(create_engine(f"sqlite:///{database}"))
    assert inspector.get_table_names() == []


def test_every_managed_connection_enables_durability_pragmas(tmp_path: Path) -> None:
    engine = create_engine_for(tmp_path / "state.db")

    with engine.connect() as connection:
        values = {
            "foreign_keys": connection.execute(text("PRAGMA foreign_keys")).scalar_one(),
            "journal_mode": connection.execute(text("PRAGMA journal_mode")).scalar_one(),
            "busy_timeout": connection.execute(text("PRAGMA busy_timeout")).scalar_one(),
            "synchronous": connection.execute(text("PRAGMA synchronous")).scalar_one(),
            "secure_delete": connection.execute(text("PRAGMA secure_delete")).scalar_one(),
        }

    assert values == {
        "foreign_keys": 1,
        "journal_mode": "wal",
        "busy_timeout": 5000,
        "synchronous": 2,
        "secure_delete": 1,
    }


def test_session_scope_commits_and_rolls_back(tmp_path: Path) -> None:
    database = tmp_path / "state.db"
    upgrade_database(database)
    engine = create_engine_for(database)
    with session_scope(engine) as session:
        session.add(SystemState(key="release", value_json='{"version": 1}'))

    with pytest.raises(RuntimeError, match="abort"), session_scope(engine) as session:
        session.add(SystemState(key="temporary", value_json="{}"))
        raise RuntimeError("abort")

    with session_scope(engine) as session:
        persisted = session.get(SystemState, "release")
        assert persisted is not None
        assert persisted.updated_at.tzinfo is UTC
        assert session.get(SystemState, "temporary") is None


def test_migration_matches_model_metadata(tmp_path: Path) -> None:
    database = tmp_path / "state.db"
    upgrade_database(database)
    engine = create_engine_for(database)

    with engine.connect() as connection:
        context = MigrationContext.configure(connection, opts={"compare_type": True})
        differences = compare_metadata(context, Base.metadata)

    assert differences == []


def test_runtime_identifiers_are_unique(tmp_path: Path) -> None:
    database = tmp_path / "state.db"
    upgrade_database(database)
    engine = create_engine_for(database)
    first_profile = _profile(
        "11111111-1111-4111-8111-111111111111", "p_abcdefghijklmnopqrstuvwxyz"
    )
    with session_scope(engine) as session:
        session.add(
            Admin(
                id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                login="owner",
                password_hash="x",
            )
        )
        session.add(first_profile)
        session.add(
            ProfileLookup(
                id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                profile_id=first_profile.id,
                kind="subscription",
                lookup_digest=b"d" * 32,
            )
        )

    with pytest.raises(IntegrityError), session_scope(engine) as session:
        session.add(
            _profile("22222222-2222-4222-8222-222222222222", "p_abcdefghijklmnopqrstuvwxyz")
        )


def test_admin_logins_are_unique(tmp_path: Path) -> None:
    database = tmp_path / "state.db"
    upgrade_database(database)
    engine = create_engine_for(database)
    with session_scope(engine) as session:
        session.add(
            Admin(
                id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                login="owner",
                password_hash="x",
            )
        )

    with pytest.raises(IntegrityError), session_scope(engine) as session:
        session.add(
            Admin(
                id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                login="owner",
                password_hash="y",
            )
        )


def test_lookup_digests_are_unique(tmp_path: Path) -> None:
    database = tmp_path / "state.db"
    upgrade_database(database)
    engine = create_engine_for(database)
    first = _profile("11111111-1111-4111-8111-111111111111", "p_abcdefghijklmnopqrstuvwxyy")
    second = _profile("22222222-2222-4222-8222-222222222222", "p_abcdefghijklmnopqrstuvwxyx")
    second_id = second.id
    with session_scope(engine) as session:
        session.add_all([first, second])
        session.add(
            ProfileLookup(
                id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                profile_id=first.id,
                kind="subscription",
                lookup_digest=b"d" * 32,
            )
        )

    with pytest.raises(IntegrityError), session_scope(engine) as session:
        session.add(
                ProfileLookup(
                    id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                    profile_id=second_id,
                kind="subscription",
                lookup_digest=b"d" * 32,
            )
        )


def _profile(profile_id: str, runtime_id: str) -> Profile:
    return Profile(
        id=profile_id,
        name="Телефон",
        state=ProfileState.PENDING,
        runtime_id=runtime_id,
        wrapped_profile_key=b"w",
        user_id_ciphertext=b"u",
        hysteria_secret_ciphertext=b"h",
        subscription_token_ciphertext=b"s",
    )
