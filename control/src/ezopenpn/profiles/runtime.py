from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable
from uuid import UUID

from ezopenpn.models import ProfileState
from ezopenpn.profiles.service import ProfileService
from ezopenpn.profiles.types import ProfileResult


@dataclass(frozen=True, slots=True)
class ReconcileResult:
    added: tuple[str, ...] = ()
    removed: tuple[str, ...] = ()
    restarted: bool = False
    error_code: str | None = None


@runtime_checkable
class RuntimeCoordinator(Protocol):
    def create(self, name: str) -> ProfileResult: ...

    def disable(self, profile_id: UUID) -> ProfileResult: ...

    def enable(self, profile_id: UUID) -> ProfileResult: ...

    def delete(self, profile_id: UUID) -> None: ...

    def reconcile(self) -> ReconcileResult: ...


class FakeRuntimeCoordinator:
    def __init__(self, profiles: ProfileService) -> None:
        self._profiles = profiles

    def create(self, name: str) -> ProfileResult:
        return self._profiles.create(name)

    def disable(self, profile_id: UUID) -> ProfileResult:
        return self._profiles.disable_local(profile_id)

    def enable(self, profile_id: UUID) -> ProfileResult:
        current = self._profiles.repository.get(profile_id)
        if current.state is ProfileState.ERROR:
            current = self._profiles.repository.set_state(profile_id, ProfileState.PENDING)
            return ProfileResult(
                profile_id=current.profile_id,
                name=current.name,
                state=current.state,
                runtime_id=current.runtime_id,
            )
        return self._profiles.enable_local(profile_id)

    def delete(self, profile_id: UUID) -> None:
        current = self._profiles.repository.get(profile_id)
        if current.state is ProfileState.ACTIVE:
            self._profiles.disable_local(profile_id)
        elif current.state is ProfileState.ERROR:
            self._profiles.repository.set_state(profile_id, ProfileState.DISABLED)
        self._profiles.repository.delete_local(profile_id)

    def reconcile(self) -> ReconcileResult:
        return ReconcileResult()
