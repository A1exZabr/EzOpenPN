from __future__ import annotations

from contextlib import suppress
from typing import Protocol
from uuid import UUID

from nacl.exceptions import CryptoError

from ezopenpn.models import ProfileState
from ezopenpn.profiles.links import ProfileLinkService
from ezopenpn.profiles.repository import (
    InvalidProfileTransition,
    ProfileNotFound,
    ProfileRepository,
)
from ezopenpn.profiles.runtime import ReconcileResult
from ezopenpn.profiles.service import ProfileService
from ezopenpn.profiles.types import (
    LinkBundle,
    ProfileRecord,
    ProfileResult,
    profile_value_context,
)
from ezopenpn.security.secrets import SecretCipher

_XRAY_ADD_FAILED = "xray_add_failed"
_RUNTIME_REVOKE_INCOMPLETE = "runtime_revoke_incomplete"
_PROFILE_MATERIAL_INVALID = "profile_material_invalid"


class XrayClient(Protocol):
    def add_user(self, runtime_id: str, user_id: UUID) -> None: ...

    def remove_user(self, runtime_id: str) -> None: ...

    def list_users(self) -> set[str]: ...

    def wait_ready(self, timeout_seconds: float) -> None: ...


class HysteriaClient(Protocol):
    def kick(self, runtime_id: str) -> None: ...


class XraySupervisorClient(Protocol):
    def restart(self) -> None: ...


class ProfileProvisioningFailed(RuntimeError):
    pass


class ProfileRevocationFailed(RuntimeError):
    pass


class ProfileEnableFailed(RuntimeError):
    pass


class ProfileDeleteFailed(RuntimeError):
    pass


class ProfileMaterialUnavailable(RuntimeError):
    pass


def _result(
    record: ProfileRecord,
    *,
    subscription_token: str | None = None,
    links: LinkBundle | None = None,
) -> ProfileResult:
    return ProfileResult(
        profile_id=record.profile_id,
        name=record.name,
        state=record.state,
        runtime_id=record.runtime_id,
        subscription_token=subscription_token,
        link_bundle=links,
    )


class ProfileCoordinator:
    def __init__(
        self,
        repository: ProfileRepository,
        cipher: SecretCipher,
        links: ProfileLinkService,
        xray: XrayClient,
        hysteria: HysteriaClient,
        supervisor: XraySupervisorClient,
        *,
        profile_service: ProfileService | None = None,
    ) -> None:
        self._repository = repository
        self._cipher = cipher
        self._links = links
        self._xray = xray
        self._hysteria = hysteria
        self._supervisor = supervisor
        self._profiles = profile_service or ProfileService(repository, cipher)

    def _user_id(self, record: ProfileRecord) -> UUID:
        if record.wrapped_profile_key is None:
            raise ProfileMaterialUnavailable("profile material is unavailable")
        try:
            profile_key = self._cipher.unwrap_profile_key(
                record.profile_id, record.wrapped_profile_key
            )
            value = self._cipher.decrypt_profile_value(
                profile_key,
                record.user_id_ciphertext,
                profile_value_context(record.profile_id, "user-id"),
            )
            return UUID(bytes=value)
        except (CryptoError, ValueError):
            raise ProfileMaterialUnavailable("profile material is unavailable") from None

    def _mark_error(self, profile_id: UUID, error_code: str) -> None:
        try:
            current = self._repository.get(profile_id)
            if current.state is ProfileState.DISABLED:
                self._repository.set_runtime_error(profile_id, error_code)
            else:
                self._repository.set_state(
                    profile_id,
                    ProfileState.ERROR,
                    error_code=error_code,
                )
        except Exception:
            return

    def create(self, name: str) -> ProfileResult:
        pending = self._profiles.create(name)
        record = self._repository.get(pending.profile_id)
        try:
            self._xray.add_user(record.runtime_id, self._user_id(record))
            active = self._repository.set_state(record.profile_id, ProfileState.ACTIVE)
            link_bundle = self._links.bundle_for_record(active)
        except Exception:
            with suppress(Exception):
                self._xray.remove_user(record.runtime_id)
            self._mark_error(record.profile_id, _XRAY_ADD_FAILED)
            raise ProfileProvisioningFailed("profile provisioning failed") from None
        return _result(
            active,
            subscription_token=pending.subscription_token,
            links=link_bundle,
        )

    def _prepare_disabled(self, profile_id: UUID) -> ProfileRecord:
        current = self._repository.get(profile_id)
        if current.state is ProfileState.PENDING:
            current = self._repository.set_state(profile_id, ProfileState.ERROR)
        return self._repository.set_state(current.profile_id, ProfileState.DISABLED)

    def disable(self, profile_id: UUID) -> ProfileResult:
        disabled = self._prepare_disabled(profile_id)
        incomplete = False
        try:
            self._hysteria.kick(disabled.runtime_id)
        except Exception:
            incomplete = True
        try:
            self._xray.remove_user(disabled.runtime_id)
        except Exception:
            incomplete = True
        try:
            self._supervisor.restart()
        except Exception:
            incomplete = True
        try:
            self._xray.wait_ready(6.0)
        except Exception:
            incomplete = True
        for active in self._repository.list():
            if active.state is not ProfileState.ACTIVE:
                continue
            try:
                self._xray.add_user(active.runtime_id, self._user_id(active))
            except Exception:
                incomplete = True
        if incomplete:
            self._repository.set_runtime_error(
                disabled.profile_id, _RUNTIME_REVOKE_INCOMPLETE
            )
            raise ProfileRevocationFailed("profile revocation incomplete")
        return _result(self._repository.get(disabled.profile_id))

    def enable(self, profile_id: UUID) -> ProfileResult:
        current = self._repository.get(profile_id)
        if current.state is ProfileState.ERROR:
            current = self._repository.set_state(profile_id, ProfileState.PENDING)
        if current.state not in {ProfileState.PENDING, ProfileState.DISABLED}:
            raise InvalidProfileTransition("profile cannot be enabled")
        try:
            self._xray.add_user(current.runtime_id, self._user_id(current))
            active = self._repository.set_state(profile_id, ProfileState.ACTIVE)
            links = self._links.bundle_for_record(active)
        except Exception:
            with suppress(Exception):
                self._xray.remove_user(current.runtime_id)
            self._mark_error(profile_id, _XRAY_ADD_FAILED)
            raise ProfileEnableFailed("profile enable failed") from None
        return _result(active, links=links)

    def delete(self, profile_id: UUID) -> None:
        try:
            self.disable(profile_id)
            self._repository.delete_local(profile_id)
            self._repository.checkpoint_wal()
        except (ProfileRevocationFailed, ProfileNotFound):
            raise
        except Exception:
            self._mark_error(profile_id, _PROFILE_MATERIAL_INVALID)
            raise ProfileDeleteFailed("profile deletion failed") from None

    def reconcile(self) -> ReconcileResult:
        return ReconcileResult()
