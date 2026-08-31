from __future__ import annotations

from dataclasses import dataclass
from threading import Lock
from typing import Protocol
from uuid import UUID

from nacl.exceptions import CryptoError

from ezopenpn.models import ProfileState
from ezopenpn.profiles.repository import ProfileRepository
from ezopenpn.profiles.runtime import ReconcileResult
from ezopenpn.profiles.types import ProfileRecord, profile_value_context
from ezopenpn.security.secrets import SecretCipher

_RECONCILE_FAILED = "runtime_reconcile_failed"


class XrayClient(Protocol):
    def add_user(self, runtime_id: str, user_id: UUID) -> None: ...

    def remove_user(self, runtime_id: str) -> None: ...

    def list_users(self) -> set[str]: ...

    def wait_ready(self, timeout_seconds: float) -> None: ...


class XraySupervisorClient(Protocol):
    def restart(self) -> None: ...


@dataclass(frozen=True, slots=True)
class RuntimeHealthSnapshot:
    ready: bool
    error_code: str | None


class RuntimeHealth:
    def __init__(self) -> None:
        self._lock = Lock()
        self._snapshot = RuntimeHealthSnapshot(
            ready=False,
            error_code=_RECONCILE_FAILED,
        )

    def update(self, result: ReconcileResult) -> None:
        with self._lock:
            self._snapshot = RuntimeHealthSnapshot(
                ready=result.error_code is None,
                error_code=result.error_code,
            )

    def snapshot(self) -> RuntimeHealthSnapshot:
        with self._lock:
            return self._snapshot


def _user_id(cipher: SecretCipher, record: ProfileRecord) -> UUID:
    if record.wrapped_profile_key is None:
        raise ValueError("profile material is unavailable")
    try:
        profile_key = cipher.unwrap_profile_key(
            record.profile_id, record.wrapped_profile_key
        )
        value = cipher.decrypt_profile_value(
            profile_key,
            record.user_id_ciphertext,
            profile_value_context(record.profile_id, "user-id"),
        )
        return UUID(bytes=value)
    except (CryptoError, ValueError):
        raise ValueError("profile material is unavailable") from None


class RuntimeReconciler:
    def __init__(
        self,
        repository: ProfileRepository,
        cipher: SecretCipher,
        xray: XrayClient,
        supervisor: XraySupervisorClient,
    ) -> None:
        self._repository = repository
        self._cipher = cipher
        self._xray = xray
        self._supervisor = supervisor
        self._lock = Lock()

    def run(self) -> ReconcileResult:
        with self._lock:
            try:
                active = tuple(
                    record
                    for record in self._repository.list()
                    if record.state is ProfileState.ACTIVE
                )
                desired = {
                    record.runtime_id: _user_id(self._cipher, record)
                    for record in active
                }
                current = self._xray.list_users()
                desired_ids = set(desired)
                missing = tuple(sorted(desired_ids - current))
                extra = tuple(sorted(current - desired_ids))

                for runtime_id in extra:
                    self._xray.remove_user(runtime_id)

                restarted = bool(extra)
                if restarted:
                    self._supervisor.restart()
                    self._xray.wait_ready(6.0)
                    for record in active:
                        self._xray.add_user(
                            record.runtime_id,
                            desired[record.runtime_id],
                        )
                else:
                    for runtime_id in missing:
                        self._xray.add_user(runtime_id, desired[runtime_id])

                return ReconcileResult(
                    added=missing,
                    removed=extra,
                    restarted=restarted,
                )
            except Exception:
                return ReconcileResult(error_code=_RECONCILE_FAILED)
