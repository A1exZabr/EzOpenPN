from __future__ import annotations

import os
import stat
import tomllib
from dataclasses import dataclass, field
from ipaddress import IPv4Address
from pathlib import Path
from typing import Self, cast

from pydantic import AnyHttpUrl, BaseModel, ConfigDict, field_validator, model_validator

_SECRET_SIZE = 32


class FrozenSettingsModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", validate_default=True)


class AppSettings(FrozenSettingsModel):
    public_ip: IPv4Address


class DatabaseSettings(FrozenSettingsModel):
    path: Path

    @field_validator("path")
    @classmethod
    def require_absolute_path(cls, value: Path) -> Path:
        if not value.is_absolute():
            raise ValueError("database_path must be absolute")
        return value


class PathSettings(FrozenSettingsModel):
    master_key_path: Path = Path("/run/secrets/ezopenpn_master_key")
    hysteria_api_path: Path = Path("/run/secrets/ezopenpn_hysteria_api")
    hysteria_obfs_path: Path = Path("/run/secrets/ezopenpn_hysteria_obfs")
    supervisor_socket: Path = Path("/run/ezopenpn-xray/control.sock")

    @field_validator(
        "master_key_path",
        "hysteria_api_path",
        "hysteria_obfs_path",
        "supervisor_socket",
    )
    @classmethod
    def require_absolute_paths(cls, value: Path) -> Path:
        if not value.is_absolute():
            raise ValueError("configured paths must be absolute")
        return value


class ProxyTrustSettings(FrozenSettingsModel):
    trusted_hosts: frozenset[str] = frozenset({"gateway"})

    @field_validator("trusted_hosts")
    @classmethod
    def require_named_hosts(cls, value: frozenset[str]) -> frozenset[str]:
        normalized = frozenset(host.strip() for host in value)
        if not normalized or "" in normalized:
            raise ValueError("trusted proxy hosts must not be empty")
        return normalized


class XraySettings(FrozenSettingsModel):
    grpc_target: str = "xray:10085"
    inbound_tag: str = "protected-entry"

    @field_validator("grpc_target", "inbound_tag")
    @classmethod
    def require_nonempty_values(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Xray settings must not be empty")
        return normalized


class HysteriaSettings(FrozenSettingsModel):
    stats_url: AnyHttpUrl = AnyHttpUrl("http://hysteria:9999")


class SessionSettings(FrozenSettingsModel):
    idle_seconds: int = 12 * 60 * 60
    absolute_seconds: int = 7 * 24 * 60 * 60

    @model_validator(mode="after")
    def validate_deadlines(self) -> Self:
        if self.idle_seconds <= 0 or self.absolute_seconds <= 0:
            raise ValueError("session deadlines must be positive")
        if self.idle_seconds > self.absolute_seconds:
            raise ValueError("session idle deadline must not exceed absolute deadline")
        return self


class Settings(FrozenSettingsModel):
    app: AppSettings
    database: DatabaseSettings
    paths: PathSettings = PathSettings()
    proxy: ProxyTrustSettings = ProxyTrustSettings()
    xray: XraySettings = XraySettings()
    hysteria: HysteriaSettings = HysteriaSettings()
    session: SessionSettings = SessionSettings()

    @property
    def public_ip(self) -> IPv4Address:
        return self.app.public_ip

    @property
    def database_path(self) -> Path:
        return self.database.path

    @property
    def xray_grpc_target(self) -> str:
        return self.xray.grpc_target

    @property
    def xray_inbound_tag(self) -> str:
        return self.xray.inbound_tag

    @property
    def hysteria_stats_url(self) -> AnyHttpUrl:
        return self.hysteria.stats_url

    @property
    def supervisor_socket(self) -> Path:
        return self.paths.supervisor_socket

    @property
    def trusted_proxy_hosts(self) -> frozenset[str]:
        return self.proxy.trusted_hosts

    @classmethod
    def load(cls, config_path: Path) -> Settings:
        with config_path.open("rb") as stream:
            loaded = cast(dict[str, object], tomllib.load(stream))

        app_value = loaded.get("app")
        if not isinstance(app_value, dict):
            raise ValueError("app configuration is required")
        app = cast(dict[str, object], dict(app_value))

        database_value = loaded.get("database", {})
        if not isinstance(database_value, dict):
            raise ValueError("database configuration must be a table")
        database = cast(dict[str, object], dict(database_value))

        legacy_database_path = app.pop("database_path", None)
        if legacy_database_path is not None:
            if "path" in database:
                raise ValueError("database path must be configured once")
            database["path"] = legacy_database_path

        normalized = dict(loaded)
        normalized["app"] = app
        normalized["database"] = database
        return cls.model_validate(normalized)


def _read_secret(path: Path) -> bytes:
    try:
        path_status = path.lstat()
    except OSError as error:
        raise ValueError(f"secret file is unavailable: {path.name}") from error
    if stat.S_ISLNK(path_status.st_mode):
        raise ValueError(f"secret file must not be a symbolic link: {path.name}")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ValueError(f"secret file could not be opened safely: {path.name}") from error

    with os.fdopen(descriptor, "rb") as stream:
        opened_status = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened_status.st_mode):
            raise ValueError(f"secret file must be regular: {path.name}")
        if stat.S_IMODE(opened_status.st_mode) != 0o600:
            raise ValueError(f"secret file must have mode 0600: {path.name}")
        value = stream.read(_SECRET_SIZE + 1)

    if len(value) != _SECRET_SIZE:
        raise ValueError(f"secret file must contain exactly 32 bytes: {path.name}")
    return value


@dataclass(frozen=True)
class SecretFiles:
    master_key: bytes = field(repr=False)
    hysteria_api_secret: bytes = field(repr=False)
    hysteria_obfs_secret: bytes = field(repr=False)

    @classmethod
    def load(
        cls,
        master_key_path: Path,
        hysteria_api_path: Path,
        hysteria_obfs_path: Path,
    ) -> SecretFiles:
        return cls(
            master_key=_read_secret(master_key_path),
            hysteria_api_secret=_read_secret(hysteria_api_path),
            hysteria_obfs_secret=_read_secret(hysteria_obfs_path),
        )

    def __repr__(self) -> str:
        return (
            "SecretFiles(master_key=<redacted>, "
            "hysteria_api_secret=<redacted>, "
            "hysteria_obfs_secret=<redacted>)"
        )
