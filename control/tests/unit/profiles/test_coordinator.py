from __future__ import annotations

from collections.abc import Callable
from ipaddress import IPv4Address
from pathlib import Path
from uuid import UUID

import pytest
from sqlalchemy import select

from ezopenpn.db import create_engine_for, session_scope, upgrade_database
from ezopenpn.integrations.xray import RuntimeUnavailable
from ezopenpn.models import AuditEvent, ProfileState
from ezopenpn.profiles.coordinator import (
    ProfileCoordinator,
    ProfileProvisioningFailed,
    ProfileRevocationFailed,
)
from ezopenpn.profiles.links import ProfileLinkService, TransportLinkConfig
from ezopenpn.profiles.reconcile import RuntimeHealth
from ezopenpn.profiles.repository import ProfileNotFound, ProfileRepository
from ezopenpn.profiles.runtime import ReconcileResult
from ezopenpn.profiles.service import ProfileService
from ezopenpn.security.secrets import SecretCipher


class RecordingRepository(ProfileRepository):
    def __init__(self, *args, events: list[str], **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._events = events

    def set_state(self, profile_id, state, error_code=None):
        result = super().set_state(profile_id, state, error_code)
        if state is ProfileState.DISABLED:
            self._events.append("database:disabled")
        return result


class FakeXray:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.reject_add = False
        self.reject_remove = False
        self.before_add: Callable[[], None] | None = None

    def add_user(self, runtime_id: str, user_id: UUID) -> None:
        del user_id
        if self.before_add is not None:
            self.before_add()
        self.events.append(f"xray:add:{runtime_id}")
        if self.reject_add:
            raise RuntimeUnavailable("Xray runtime unavailable")

    def remove_user(self, runtime_id: str) -> None:
        self.events.append(f"xray:remove:{runtime_id}")
        if self.reject_remove:
            raise RuntimeUnavailable("Xray runtime unavailable")

    def list_users(self) -> set[str]:
        return set()

    def wait_ready(self, timeout_seconds: float) -> None:
        assert timeout_seconds == 6.0
        self.events.append("xray:ready")


class FakeHysteria:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.reject = False

    def kick(self, runtime_id: str) -> None:
        self.events.append(f"hysteria:kick:{runtime_id}")
        if self.reject:
            raise RuntimeError("private upstream detail")


class FakeSupervisor:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    def restart(self) -> None:
        self.events.append("xray:restart")


class FakeReconciler:
    def __init__(self) -> None:
        self.runs = 0
        self.result = ReconcileResult()

    def run(self) -> ReconcileResult:
        self.runs += 1
        return self.result


class CoordinatorFixture:
    def __init__(self, tmp_path: Path) -> None:
        self.events: list[str] = []
        database = tmp_path / "state.db"
        upgrade_database(database)
        engine = create_engine_for(database)
        self.engine = engine
        self.cipher = SecretCipher(bytes(range(32)))
        self.repository = RecordingRepository(engine, self.cipher, events=self.events)
        random_values = iter(
            (
                b"a" * 32,
                b"b" * 32,
                b"c" * 17,
                b"d" * 32,
                b"e" * 32,
                b"f" * 17,
            )
        )
        identifiers = iter(
            (
                UUID("11111111-1111-4111-8111-111111111111"),
                UUID("22222222-2222-4222-8222-222222222222"),
                UUID("33333333-3333-4333-8333-333333333333"),
                UUID("44444444-4444-4444-8444-444444444444"),
            )
        )

        def random_bytes(size: int) -> bytes:
            value = next(random_values)
            assert len(value) == size
            return value

        profile_service = ProfileService(
            self.repository,
            self.cipher,
            random_bytes=random_bytes,
            uuid_factory=lambda: next(identifiers),
        )
        links = ProfileLinkService(
            self.repository,
            self.cipher,
            TransportLinkConfig(
                host=IPv4Address("203.0.113.10"),
                reality_public_key="public-key",
                reality_server_name="www.example.org",
                reality_short_id="a1b2c3d4e5f60708",
                xhttp_path="/coordinator-test",
                hysteria_obfs_password="obfs-value",
            ),
        )
        self.xray = FakeXray(self.events)
        self.hysteria = FakeHysteria(self.events)
        self.supervisor = FakeSupervisor(self.events)
        self.reconciler = FakeReconciler()
        self.health = RuntimeHealth()
        self.coordinator = ProfileCoordinator(
            self.repository,
            self.cipher,
            links,
            self.xray,
            self.hysteria,
            self.supervisor,
            profile_service=profile_service,
            reconciler=self.reconciler,
            runtime_health=self.health,
        )


@pytest.fixture
def fixture(tmp_path: Path) -> CoordinatorFixture:
    return CoordinatorFixture(tmp_path)


def test_create_returns_links_only_after_runtime_is_active(
    fixture: CoordinatorFixture,
) -> None:
    result = fixture.coordinator.create("Телефон")

    assert result.state is ProfileState.ACTIVE
    assert result.link_bundle is not None
    assert result.link_bundle.vless_link.startswith("vless://")
    assert result.link_bundle.hysteria_link.startswith("hysteria2://")
    assert fixture.events[0].startswith("xray:add:")


def test_failed_create_never_returns_links(fixture: CoordinatorFixture) -> None:
    fixture.xray.reject_add = True

    with pytest.raises(ProfileProvisioningFailed) as captured:
        fixture.coordinator.create("Телефон")

    stored = fixture.repository.list()
    assert len(stored) == 1
    assert stored[0].state is ProfileState.ERROR
    assert stored[0].last_error_code == "xray_add_failed"
    assert "private" not in str(captured.value)
    assert fixture.reconciler.runs == 1


def test_failed_mutation_propagates_reconcile_health(
    fixture: CoordinatorFixture,
) -> None:
    fixture.xray.reject_add = True
    fixture.reconciler.result = ReconcileResult(
        error_code="runtime_reconcile_failed"
    )

    with pytest.raises(ProfileProvisioningFailed):
        fixture.coordinator.create("Телефон")

    assert fixture.health.snapshot().ready is False
    assert fixture.health.snapshot().error_code == "runtime_reconcile_failed"


def test_disable_blocks_auth_before_every_revocation_phase(
    fixture: CoordinatorFixture,
) -> None:
    first = fixture.coordinator.create("Телефон")
    second = fixture.coordinator.create("Ноутбук")
    fixture.events.clear()

    result = fixture.coordinator.disable(first.profile_id)

    assert result.state is ProfileState.DISABLED
    assert fixture.events == [
        "database:disabled",
        f"hysteria:kick:{first.runtime_id}",
        f"xray:remove:{first.runtime_id}",
        "xray:restart",
        "xray:ready",
        f"xray:add:{second.runtime_id}",
    ]


def test_disable_attempts_every_phase_after_an_earlier_failure(
    fixture: CoordinatorFixture,
) -> None:
    first = fixture.coordinator.create("Телефон")
    second = fixture.coordinator.create("Ноутбук")
    fixture.events.clear()
    fixture.hysteria.reject = True
    fixture.xray.reject_remove = True

    with pytest.raises(ProfileRevocationFailed) as captured:
        fixture.coordinator.disable(first.profile_id)

    assert fixture.repository.get(first.profile_id).state is ProfileState.DISABLED
    assert fixture.repository.get(first.profile_id).last_error_code == (
        "runtime_revoke_incomplete"
    )
    assert fixture.events == [
        "database:disabled",
        f"hysteria:kick:{first.runtime_id}",
        f"xray:remove:{first.runtime_id}",
        "xray:restart",
        "xray:ready",
        f"xray:add:{second.runtime_id}",
    ]
    assert "private upstream detail" not in str(captured.value)


def test_enable_adds_runtime_user_before_committing_active_state(
    fixture: CoordinatorFixture,
) -> None:
    created = fixture.coordinator.create("Телефон")
    fixture.coordinator.disable(created.profile_id)
    observed: list[ProfileState] = []
    fixture.xray.before_add = lambda: observed.append(
        fixture.repository.get(created.profile_id).state
    )

    enabled = fixture.coordinator.enable(created.profile_id)

    assert observed == [ProfileState.DISABLED]
    assert enabled.state is ProfileState.ACTIVE
    assert enabled.link_bundle is not None


def test_delete_removes_secret_rows_and_leaves_only_safe_audit(
    fixture: CoordinatorFixture,
) -> None:
    created = fixture.coordinator.create("Планшет")

    fixture.coordinator.delete(created.profile_id)

    with pytest.raises(ProfileNotFound):
        fixture.repository.get(created.profile_id)
    with session_scope(fixture.engine) as session:
        audit = session.scalar(select(AuditEvent))
        assert audit is not None
        assert audit.event_type == "profile_deleted"
        assert audit.subject_id is None
        assert audit.details_json == "{}"


def test_delete_preserves_not_found_result(fixture: CoordinatorFixture) -> None:
    missing = UUID("99999999-9999-4999-8999-999999999999")

    with pytest.raises(ProfileNotFound):
        fixture.coordinator.delete(missing)
