import re
from pathlib import Path
from uuid import UUID

import pytest

from ezopenpn.db import create_engine_for, upgrade_database
from ezopenpn.models import ProfileState
from ezopenpn.profiles.repository import ProfileRepository
from ezopenpn.profiles.service import InvalidProfileName, ProfileService
from ezopenpn.security.secrets import SecretCipher


def _service(tmp_path: Path) -> tuple[ProfileService, bytes]:
    database = tmp_path / "state.db"
    upgrade_database(database)
    engine = create_engine_for(database)
    plain_hysteria = b"h" * 32
    values = iter((plain_hysteria, b"s" * 32, b"r" * 17))
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
    service = ProfileService(
        repository,
        cipher,
        random_bytes=deterministic_bytes,
        uuid_factory=lambda: next(identifiers),
    )
    return service, plain_hysteria


def test_profile_creation_encrypts_all_credentials(tmp_path: Path) -> None:
    service, plain_hysteria = _service(tmp_path)

    result = service.create("  Телефон  ")
    stored = service.repository.get(result.profile_id)

    assert result.name == "Телефон"
    assert stored.state is ProfileState.PENDING
    assert plain_hysteria not in stored.hysteria_secret_ciphertext
    assert stored.wrapped_profile_key
    assert result.subscription_token is not None
    assert stored.subscription_lookup_digest != result.subscription_token.encode()
    assert re.fullmatch(r"p_[a-z2-7]{26}", result.runtime_id)


def test_profile_result_repr_redacts_issued_token(tmp_path: Path) -> None:
    service, _ = _service(tmp_path)

    result = service.create("Телефон")

    assert result.subscription_token is not None
    assert result.subscription_token not in repr(result)


@pytest.mark.parametrize("name", ["", " " * 4, "x" * 65, "ok\nroot"])
def test_profile_name_validation_rejects_unsafe_values(tmp_path: Path, name: str) -> None:
    service, _ = _service(tmp_path)

    with pytest.raises(InvalidProfileName):
        service.create(name)


def test_disable_local_changes_an_active_profile(tmp_path: Path) -> None:
    service, _ = _service(tmp_path)
    created = service.create("Телефон")
    service.repository.set_state(created.profile_id, ProfileState.ACTIVE)

    disabled = service.disable_local(created.profile_id)

    assert disabled.state is ProfileState.DISABLED
