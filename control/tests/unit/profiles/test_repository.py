from datetime import datetime
from pathlib import Path
from uuid import UUID

import pytest
from sqlalchemy import Engine

from ezopenpn.db import create_engine_for, upgrade_database
from ezopenpn.models import ProfileState
from ezopenpn.profiles.repository import InvalidProfileTransition, ProfileRepository
from ezopenpn.profiles.service import ProfileService
from ezopenpn.security.secrets import SecretCipher


def _service(tmp_path: Path) -> tuple[Engine, ProfileService]:
    database = tmp_path / "state.db"
    upgrade_database(database)
    engine = create_engine_for(database)
    values = iter((b"h" * 32, b"s" * 32, b"r" * 17))
    identifiers = iter(
        (
            UUID("11111111-1111-4111-8111-111111111111"),
            UUID("22222222-2222-4222-8222-222222222222"),
        )
    )

    def deterministic_bytes(size: int) -> bytes:
        value = next(values)
        assert len(value) == size
        return value

    cipher = SecretCipher(bytes(range(32)))
    repository = ProfileRepository(engine, cipher)
    return engine, ProfileService(
        repository,
        cipher,
        random_bytes=deterministic_bytes,
        uuid_factory=lambda: next(identifiers),
    )


def test_repository_finds_profile_by_presented_subscription_token(tmp_path: Path) -> None:
    _, service = _service(tmp_path)
    created = service.create("Телефон")

    found = service.repository.find_by_subscription_token(created.subscription_token or "")

    assert found is not None
    assert found.profile_id == created.profile_id
    assert service.repository.find_by_subscription_token("unknown-token") is None


def test_invalid_transition_is_rejected(tmp_path: Path) -> None:
    _, service = _service(tmp_path)
    created = service.create("Ноутбук")
    service.repository.set_state(created.profile_id, ProfileState.ERROR)
    service.repository.set_state(created.profile_id, ProfileState.DISABLED)

    with pytest.raises(InvalidProfileTransition):
        service.repository.set_state(created.profile_id, ProfileState.PENDING)


def test_all_declared_state_transitions_are_available(tmp_path: Path) -> None:
    _, service = _service(tmp_path)
    created = service.create("Планшет")

    service.repository.set_state(created.profile_id, ProfileState.ACTIVE)
    service.repository.set_state(created.profile_id, ProfileState.DISABLED)
    service.repository.set_state(created.profile_id, ProfileState.ACTIVE)
    service.repository.set_state(created.profile_id, ProfileState.ERROR)
    final = service.repository.set_state(created.profile_id, ProfileState.PENDING)

    assert final.state is ProfileState.PENDING


def test_state_transition_rejects_a_naive_clock(tmp_path: Path) -> None:
    engine, service = _service(tmp_path)
    created = service.create("Планшет")
    repository = ProfileRepository(
        engine,
        SecretCipher(bytes(range(32))),
        clock=lambda: datetime(2026, 8, 31, 10, 0),
    )

    with pytest.raises(ValueError, match="timezone"):
        repository.set_state(created.profile_id, ProfileState.ACTIVE)
