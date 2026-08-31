from __future__ import annotations

from pathlib import Path
from uuid import UUID

from ezopenpn.db import create_engine_for, upgrade_database
from ezopenpn.models import ProfileState
from ezopenpn.profiles.reconcile import RuntimeHealth, RuntimeReconciler
from ezopenpn.profiles.repository import ProfileRepository
from ezopenpn.profiles.service import ProfileService
from ezopenpn.security.secrets import SecretCipher


class FakeXray:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.users: set[str] = set()
        self.reject_list = False

    def add_user(self, runtime_id: str, user_id: UUID) -> None:
        del user_id
        self.events.append(f"xray:add:{runtime_id}")
        self.users.add(runtime_id)

    def remove_user(self, runtime_id: str) -> None:
        self.events.append(f"xray:remove:{runtime_id}")
        self.users.discard(runtime_id)

    def list_users(self) -> set[str]:
        self.events.append("xray:list")
        if self.reject_list:
            raise RuntimeError("private runtime address")
        return set(self.users)

    def wait_ready(self, timeout_seconds: float) -> None:
        assert timeout_seconds == 6.0
        self.events.append("xray:ready")


class FakeSupervisor:
    def __init__(self, events: list[str], xray: FakeXray) -> None:
        self.events = events
        self.xray = xray

    def restart(self) -> None:
        self.events.append("xray:restart")
        self.xray.users.clear()


class ReconcileFixture:
    def __init__(self, tmp_path: Path) -> None:
        database = tmp_path / "state.db"
        upgrade_database(database)
        engine = create_engine_for(database)
        self.cipher = SecretCipher(bytes(range(32)))
        self.repository = ProfileRepository(engine, self.cipher)
        profiles = ProfileService(self.repository, self.cipher)
        first = profiles.create("Телефон")
        second = profiles.create("Ноутбук")
        self.first = self.repository.set_state(first.profile_id, ProfileState.ACTIVE)
        self.second = self.repository.set_state(second.profile_id, ProfileState.ACTIVE)
        self.events: list[str] = []
        self.xray = FakeXray(self.events)
        self.health = RuntimeHealth()
        self.reconciler = RuntimeReconciler(
            self.repository,
            self.cipher,
            self.xray,
            FakeSupervisor(self.events, self.xray),
        )


def test_reconcile_adds_missing_and_removes_extra(tmp_path: Path) -> None:
    fixture = ReconcileFixture(tmp_path)
    fixture.xray.users = {fixture.second.runtime_id, "p_unknown"}

    result = fixture.reconciler.run()

    assert result.added == (fixture.first.runtime_id,)
    assert result.removed == ("p_unknown",)
    assert result.restarted is True
    active_order = [
        record.runtime_id
        for record in fixture.repository.list()
        if record.state is ProfileState.ACTIVE
    ]
    assert fixture.events == [
        "xray:list",
        "xray:remove:p_unknown",
        "xray:restart",
        "xray:ready",
        *(f"xray:add:{runtime_id}" for runtime_id in active_order),
    ]
    assert fixture.xray.users == {fixture.first.runtime_id, fixture.second.runtime_id}


def test_reconcile_without_extras_adds_only_missing(tmp_path: Path) -> None:
    fixture = ReconcileFixture(tmp_path)
    fixture.xray.users = {fixture.second.runtime_id}

    result = fixture.reconciler.run()

    assert result.added == (fixture.first.runtime_id,)
    assert result.removed == ()
    assert result.restarted is False
    assert fixture.events == [
        "xray:list",
        f"xray:add:{fixture.first.runtime_id}",
    ]


def test_disabled_profile_is_removed_from_runtime(tmp_path: Path) -> None:
    fixture = ReconcileFixture(tmp_path)
    fixture.repository.set_state(fixture.first.profile_id, ProfileState.DISABLED)
    fixture.xray.users = {fixture.first.runtime_id, fixture.second.runtime_id}

    result = fixture.reconciler.run()

    assert result.removed == (fixture.first.runtime_id,)
    assert result.restarted is True
    assert fixture.xray.users == {fixture.second.runtime_id}


def test_runtime_error_is_fixed_and_safe(tmp_path: Path) -> None:
    fixture = ReconcileFixture(tmp_path)
    fixture.xray.reject_list = True

    result = fixture.reconciler.run()
    fixture.health.update(result)

    assert result.error_code == "runtime_reconcile_failed"
    assert "private runtime address" not in repr(result)
    assert fixture.health.snapshot().ready is False
    assert fixture.health.snapshot().error_code == "runtime_reconcile_failed"
