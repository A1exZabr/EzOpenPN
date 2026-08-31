from __future__ import annotations

import argparse
import base64
import json
import os
import re
import shutil
import stat
# Validator subprocesses use fixed argument vectors and never invoke a shell.
import subprocess  # nosec B404
import sys
import tempfile
from pathlib import Path
from typing import Self

import yaml
from jinja2 import Environment, FileSystemLoader, StrictUndefined
from pydantic import BaseModel, ConfigDict, ValidationError, field_validator, model_validator

_ROOT = Path(__file__).resolve().parents[1]
_TEMPLATE_ROOT = _ROOT / "deploy"
_MAX_VALUES_BYTES = 64 * 1024
_HOST_PATTERN = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
)
_SHORT_ID_PATTERN = re.compile(r"(?:[0-9a-f]{2}){1,8}")
_INBOUND_TAG_PATTERN = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")


class RuntimeConfigError(RuntimeError):
    pass


class FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class FallbackLimit(FrozenModel):
    after_bytes: int
    bytes_per_second: int
    burst_bytes_per_second: int

    @model_validator(mode="after")
    def validate_limits(self) -> Self:
        if not 1_048_576 <= self.after_bytes <= 67_108_864:
            raise ValueError("fallback threshold is outside the supported range")
        if not 131_072 <= self.bytes_per_second <= 8_388_608:
            raise ValueError("fallback rate is outside the supported range")
        if not self.bytes_per_second <= self.burst_bytes_per_second <= 33_554_432:
            raise ValueError("fallback burst is outside the supported range")
        return self


class XrayValues(FrozenModel):
    target: str
    server_name: str
    private_key: str
    short_id: str
    xhttp_path: str
    fallback_upload: FallbackLimit
    fallback_download: FallbackLimit
    # These bind only inside isolated containers; Compose controls every host publish.
    listen: str = "0.0.0.0"  # nosec B104
    port: int = 8443
    api_listen: str = "0.0.0.0"  # nosec B104
    api_port: int = 10085
    inbound_tag: str = "protected-entry"

    @field_validator("server_name")
    @classmethod
    def validate_server_name(cls, value: str) -> str:
        normalized = value.strip().lower()
        if _HOST_PATTERN.fullmatch(normalized) is None:
            raise ValueError("server name is invalid")
        return normalized

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        host, separator, port = value.rpartition(":")
        if separator != ":" or port != "443" or _HOST_PATTERN.fullmatch(host) is None:
            raise ValueError("target is invalid")
        return value

    @field_validator("private_key")
    @classmethod
    def validate_private_key(cls, value: str) -> str:
        if not value.isascii() or not 42 <= len(value) <= 44:
            raise ValueError("Reality private key is invalid")
        try:
            decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        except ValueError:
            raise ValueError("Reality private key is invalid") from None
        if len(decoded) != 32:
            raise ValueError("Reality private key is invalid")
        return value

    @field_validator("short_id")
    @classmethod
    def validate_short_id(cls, value: str) -> str:
        if _SHORT_ID_PATTERN.fullmatch(value) is None:
            raise ValueError("Reality short ID is invalid")
        return value

    @field_validator("xhttp_path")
    @classmethod
    def validate_xhttp_path(cls, value: str) -> str:
        if (
            not value.startswith("/")
            or len(value) > 256
            or any(character in value for character in "?#\r\n")
        ):
            raise ValueError("XHTTP path is invalid")
        return value

    @field_validator("listen", "api_listen")
    @classmethod
    def require_container_listener(cls, value: str) -> str:
        # Reject alternate listeners so the container topology stays deterministic.
        if value != "0.0.0.0":  # nosec B104
            raise ValueError("runtime listeners must be IPv4-only container listeners")
        return value

    @field_validator("port")
    @classmethod
    def require_public_port(cls, value: int) -> int:
        if value != 8443:
            raise ValueError("Xray public container port is fixed")
        return value

    @field_validator("api_port")
    @classmethod
    def require_api_port(cls, value: int) -> int:
        if value != 10085:
            raise ValueError("Xray API port is fixed")
        return value

    @field_validator("inbound_tag")
    @classmethod
    def validate_inbound_tag(cls, value: str) -> str:
        if _INBOUND_TAG_PATTERN.fullmatch(value) is None:
            raise ValueError("Xray inbound tag is invalid")
        return value

    @model_validator(mode="after")
    def require_target_name_match(self) -> Self:
        if self.target != f"{self.server_name}:443":
            raise ValueError("Reality target and server name must match")
        if self.fallback_upload == self.fallback_download:
            raise ValueError("fallback limits must not be identical")
        return self


class HysteriaValues(FrozenModel):
    certificate_path: Path
    private_key_path: Path
    obfs_password: str
    stats_secret: str
    listen: str = "0.0.0.0:8443"
    auth_url: str = "http://control:8000/internal/hysteria/auth"
    stats_listen: str = "0.0.0.0:9999"

    @field_validator("certificate_path", "private_key_path")
    @classmethod
    def require_absolute_file_path(cls, value: Path) -> Path:
        if not value.is_absolute() or "\x00" in str(value):
            raise ValueError("certificate paths must be absolute")
        return value

    @field_validator("obfs_password", "stats_secret")
    @classmethod
    def validate_runtime_secret(cls, value: str) -> str:
        if not 16 <= len(value) <= 256 or not value.isascii():
            raise ValueError("runtime secret is invalid")
        return value

    @field_validator("listen")
    @classmethod
    def require_public_listener(cls, value: str) -> str:
        if value != "0.0.0.0:8443":
            raise ValueError("Hysteria2 public container listener is fixed")
        return value

    @field_validator("auth_url")
    @classmethod
    def require_internal_auth(cls, value: str) -> str:
        if value != "http://control:8000/internal/hysteria/auth":
            raise ValueError("Hysteria2 auth endpoint is fixed")
        return value

    @field_validator("stats_listen")
    @classmethod
    def require_internal_stats(cls, value: str) -> str:
        if value != "0.0.0.0:9999":
            raise ValueError("Hysteria2 stats listener is fixed")
        return value


class RuntimeValues(FrozenModel):
    xray: XrayValues
    hysteria: HysteriaValues


def _load_values(path: Path) -> RuntimeValues:
    try:
        status = path.lstat()
        if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
            raise RuntimeConfigError("values file must be a regular file")
        raw = path.read_bytes()
    except OSError:
        raise RuntimeConfigError("values file is unavailable") from None
    if len(raw) > _MAX_VALUES_BYTES:
        raise RuntimeConfigError("values file is too large")
    try:
        loaded = json.loads(raw)
        return RuntimeValues.model_validate(loaded)
    except (json.JSONDecodeError, UnicodeDecodeError, ValidationError, TypeError):
        raise RuntimeConfigError("runtime values are invalid") from None


def _environment() -> Environment:
    return Environment(
        loader=FileSystemLoader(_TEMPLATE_ROOT),
        undefined=StrictUndefined,
        autoescape=True,
        keep_trailing_newline=True,
    )


def _render(values: RuntimeValues) -> tuple[str, str]:
    environment = _environment()
    context = values.model_dump(mode="json")
    try:
        masquerade = (_TEMPLATE_ROOT / "masquerade" / "index.html").read_text(
            encoding="utf-8"
        )
        xray = environment.get_template("xray/config.json.tmpl").render(**context)
        hysteria = environment.get_template("hysteria/config.yaml.tmpl").render(
            **context,
            masquerade_content=masquerade,
        )
    except Exception:
        raise RuntimeConfigError("runtime templates could not be rendered") from None
    return xray, hysteria


def _validate_structure(xray: str, hysteria: str) -> None:
    try:
        xray_config = json.loads(xray)
        hysteria_config = yaml.safe_load(hysteria)
    except (json.JSONDecodeError, yaml.YAMLError):
        raise RuntimeConfigError("rendered runtime configuration is invalid") from None
    if not isinstance(xray_config, dict) or not isinstance(hysteria_config, dict):
        raise RuntimeConfigError("rendered runtime configuration is invalid")


def _write_temporary(parent: Path, name: str, content: str) -> Path:
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    stem, suffix = os.path.splitext(name)
    descriptor, raw_path = tempfile.mkstemp(
        prefix=f".{stem}.", suffix=suffix, dir=parent
    )
    path = Path(raw_path)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return path


def _validate_xray(binary: Path, config: Path) -> None:
    try:
        # The caller supplies a validated executable path; arguments remain fixed.
        result = subprocess.run(  # nosec B603
            [str(binary), "run", "-test", "-config", str(config)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeConfigError("Xray validation could not run") from None
    if result.returncode != 0:
        raise RuntimeConfigError("Xray rejected the rendered configuration")


def _validate_hysteria(binary: Path, config: Path) -> None:
    environment = dict(os.environ)
    environment["HYSTERIA_DISABLE_UPDATE_CHECK"] = "1"
    try:
        # The caller supplies a validated executable path; arguments remain fixed.
        process = subprocess.Popen(  # nosec B603
            [str(binary), "server", "-c", str(config), "-l", "error"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=environment,
        )
    except OSError:
        raise RuntimeConfigError("Hysteria2 validation could not run") from None
    try:
        return_code = process.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            process.wait(timeout=3.0)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3.0)
        return
    if return_code != 0:
        raise RuntimeConfigError("Hysteria2 rejected the rendered configuration")
    raise RuntimeConfigError("Hysteria2 validation stopped unexpectedly")


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def render_runtime_configs(
    values_path: Path,
    output_root: Path,
    *,
    xray_binary: Path | None = None,
    hysteria_binary: Path | None = None,
) -> None:
    if (xray_binary is None) != (hysteria_binary is None):
        raise RuntimeConfigError("both runtime validators must be provided together")
    values = _load_values(values_path)
    xray_content, hysteria_content = _render(values)
    _validate_structure(xray_content, hysteria_content)

    xray_parent = output_root / "xray"
    hysteria_parent = output_root / "hysteria"
    xray_temporary: Path | None = None
    hysteria_temporary: Path | None = None
    try:
        xray_temporary = _write_temporary(xray_parent, "config.json", xray_content)
        hysteria_temporary = _write_temporary(
            hysteria_parent,
            "config.yaml",
            hysteria_content,
        )
        if xray_binary is not None and hysteria_binary is not None:
            _validate_xray(xray_binary, xray_temporary)
            _validate_hysteria(hysteria_binary, hysteria_temporary)
        os.replace(xray_temporary, xray_parent / "config.json")
        _fsync_directory(xray_parent)
        os.replace(hysteria_temporary, hysteria_parent / "config.yaml")
        _fsync_directory(hysteria_parent)
    except Exception:
        if xray_temporary is not None:
            xray_temporary.unlink(missing_ok=True)
        if hysteria_temporary is not None:
            hysteria_temporary.unlink(missing_ok=True)
        raise


def _binary(value: str | None, fallback: str) -> Path | None:
    if value is not None:
        return Path(value)
    discovered = shutil.which(fallback)
    return Path(discovered) if discovered is not None else None


def main() -> int:
    parser = argparse.ArgumentParser(description="Render protected runtime configuration")
    parser.add_argument("--values", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--xray-bin")
    parser.add_argument("--hysteria-bin")
    parser.add_argument("--require-runtime-validation", action="store_true")
    arguments = parser.parse_args()

    xray_binary = _binary(arguments.xray_bin, "xray")
    hysteria_binary = _binary(arguments.hysteria_bin, "hysteria")
    if arguments.require_runtime_validation and (
        xray_binary is None or hysteria_binary is None
    ):
        print("Runtime validators are unavailable.", file=sys.stderr)
        return 2
    if xray_binary is None or hysteria_binary is None:
        xray_binary = None
        hysteria_binary = None
    try:
        render_runtime_configs(
            arguments.values,
            arguments.output_root,
            xray_binary=xray_binary,
            hysteria_binary=hysteria_binary,
        )
    except RuntimeConfigError as error:
        print(str(error), file=sys.stderr)
        return 2
    print("Runtime configuration is ready.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
