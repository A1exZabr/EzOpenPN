from __future__ import annotations

import json
import os
import shutil
import socket
import stat
import subprocess
import time
from pathlib import Path
from uuid import UUID, uuid4

import httpx
import pytest
import yaml
from tools.render_runtime_config import RuntimeConfigError, render_runtime_configs

from ezopenpn.integrations.hysteria import HttpHysteriaClient
from ezopenpn.integrations.xray import GrpcXrayClient

_ROOT = Path(__file__).resolve().parents[2]
_COMPOSE_FILE = _ROOT / "tests" / "compose" / "runtime-compose.yaml"
_RUNTIME_ID = "p_abcdefghijklmnopqrstuvwx23"
_TEST_VALUES_TO_REDACT = (
    "profile-auth-value-1234",
    "test-obfs-value-1234",
    "test-stats-value-5678",
    "UG2LfxKeyggwo4VTtVe2jycx85N1csWWomkiPdqE-nc",
)


def _values() -> dict[str, object]:
    return {
        "xray": {
            "target": "www.example.org:443",
            "server_name": "www.example.org",
            "private_key": "UG2LfxKeyggwo4VTtVe2jycx85N1csWWomkiPdqE-nc",
            "short_id": "a1b2c3d4e5f60708",
            "xhttp_path": "/runtime-check",
            "fallback_upload": {
                "after_bytes": 9437184,
                "bytes_per_second": 786432,
                "burst_bytes_per_second": 3145728,
            },
            "fallback_download": {
                "after_bytes": 11534336,
                "bytes_per_second": 1048576,
                "burst_bytes_per_second": 4194304,
            },
        },
        "hysteria": {
            "certificate_path": "/certs/fullchain.pem",
            "private_key_path": "/certs/privkey.pem",
            "obfs_password": "test-obfs-value-1234",
            "stats_secret": "test-stats-value-5678",
        },
    }


@pytest.fixture
def rendered(tmp_path: Path) -> Path:
    values_path = tmp_path / "values.json"
    values_path.write_text(json.dumps(_values()), encoding="utf-8")
    output = tmp_path / "rendered"
    render_runtime_configs(values_path, output)
    return output


def test_rendered_xray_config_has_no_static_profiles(rendered: Path) -> None:
    config = json.loads((rendered / "xray" / "config.json").read_text())
    inbound = next(
        item for item in config["inbounds"] if item["tag"] == "protected-entry"
    )

    assert inbound["settings"]["clients"] == []
    assert inbound["streamSettings"]["network"] == "xhttp"
    assert inbound["streamSettings"]["xhttpSettings"] == {
        "mode": "auto",
        "path": "/runtime-check",
    }
    reality = inbound["streamSettings"]["realitySettings"]
    assert reality["show"] is False
    assert reality["target"] == "www.example.org:443"
    assert reality["limitFallbackUpload"]["bytesPerSec"] == 786432
    assert config["api"] == {"tag": "api", "services": ["HandlerService"]}


def test_rendered_hysteria_is_fail_closed(rendered: Path) -> None:
    config = yaml.safe_load((rendered / "hysteria" / "config.yaml").read_text())

    assert config["auth"]["type"] == "http"
    assert config["auth"]["http"]["url"] == (
        "http://control:8000/internal/hysteria/auth"
    )
    assert config["obfs"]["type"] == "salamander"
    assert config["trafficStats"]["listen"] == "0.0.0.0:9999"
    assert config["trafficStats"]["secret"] == "test-stats-value-5678"
    assert config["masquerade"]["type"] == "string"
    assert "EzOpenPN" in config["masquerade"]["string"]["content"]


def test_rendered_files_are_private(rendered: Path) -> None:
    for path in (
        rendered / "xray" / "config.json",
        rendered / "hysteria" / "config.yaml",
    ):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_unknown_values_fail_without_partial_output(tmp_path: Path) -> None:
    values = _values()
    values["unexpected"] = True
    values_path = tmp_path / "values.json"
    values_path.write_text(json.dumps(values), encoding="utf-8")
    output = tmp_path / "rendered"

    with pytest.raises(RuntimeConfigError):
        render_runtime_configs(values_path, output)

    assert not (output / "xray" / "config.json").exists()
    assert not (output / "hysteria" / "config.yaml").exists()


def test_invalid_xhttp_path_is_rejected(tmp_path: Path) -> None:
    values = _values()
    values["xray"]["xhttp_path"] = "missing-leading-slash"  # type: ignore[index]
    values_path = tmp_path / "values.json"
    values_path.write_text(json.dumps(values), encoding="utf-8")

    with pytest.raises(RuntimeConfigError):
        render_runtime_configs(values_path, tmp_path / "rendered")


def test_validator_temporary_files_keep_runtime_extensions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    values_path = tmp_path / "values.json"
    values_path.write_text(json.dumps(_values()), encoding="utf-8")
    observed: list[str] = []

    def record_xray(binary: Path, config: Path) -> None:
        del binary
        observed.append(config.suffix)

    def record_hysteria(binary: Path, config: Path) -> None:
        del binary
        observed.append(config.suffix)

    monkeypatch.setattr("tools.render_runtime_config._validate_xray", record_xray)
    monkeypatch.setattr(
        "tools.render_runtime_config._validate_hysteria", record_hysteria
    )

    render_runtime_configs(
        values_path,
        tmp_path / "rendered",
        xray_binary=Path("/test/xray"),
        hysteria_binary=Path("/test/hysteria"),
    )

    assert observed == [".json", ".yaml"]


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    return (
        subprocess.run(
            ["docker", "info"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=10,
        ).returncode
        == 0
    )


def _run(command: list[str], *, environment: dict[str, str]) -> str:
    result = subprocess.run(
        command,
        cwd=_ROOT,
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
        timeout=180,
    )
    if result.returncode != 0:
        diagnostic = _redact("\n".join((result.stdout, result.stderr)))
        raise RuntimeError(f"runtime integration command failed: {diagnostic}")
    return result.stdout.strip()


def _redact(value: str) -> str:
    sanitized = value.strip()[-2000:]
    for test_value in _TEST_VALUES_TO_REDACT:
        sanitized = sanitized.replace(test_value, "<redacted>")
    return sanitized


def _wait_for(callback, *, timeout: float = 45.0) -> object:
    deadline = time.monotonic() + timeout
    while True:
        try:
            result = callback()
            if result:
                return result
        except (OSError, httpx.HTTPError):
            pass
        if time.monotonic() >= deadline:
            raise RuntimeError("runtime integration timed out")
        time.sleep(0.2)


def _published_port(
    service: str, container_port: int, *, project: str, environment: dict[str, str]
) -> int:
    output = _run(
        [
            "docker",
            "compose",
            "-f",
            str(_COMPOSE_FILE),
            "--project-name",
            project,
            "port",
            service,
            str(container_port),
        ],
        environment=environment,
    )
    return int(output.splitlines()[-1].rsplit(":", 1)[1])


def _socket_ready(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
        connection.settimeout(0.2)
        return connection.connect_ex(("127.0.0.1", port)) == 0


def _socks_request_ready(port: int, *, environment: dict[str, str]) -> bool:
    result = subprocess.run(
        [
            "curl",
            "--fail",
            "--silent",
            "--show-error",
            "--max-time",
            "3",
            "--output",
            "/dev/null",
            "--socks5-hostname",
            f"127.0.0.1:{port}",
            "http://target:8080/",
        ],
        cwd=_ROOT,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=5,
    )
    return result.returncode == 0


def _runtime_logs(
    compose: list[str], *, environment: dict[str, str]
) -> str:
    logs = subprocess.run(
        [
            *compose,
            "logs",
            "--no-color",
            "--tail",
            "120",
            "control",
            "target",
            "client",
            "hysteria",
        ],
        cwd=_ROOT,
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )
    return _redact(logs.stdout + logs.stderr)


@pytest.mark.integration
def test_real_runtimes_accept_management_and_revocation(
    tmp_path: Path, request: pytest.FixtureRequest
) -> None:
    if "integration" not in request.config.option.markexpr:
        pytest.skip("run with the integration marker selected")
    if not _docker_available():
        pytest.skip("local container runtime is unavailable")

    certificate_root = tmp_path / "certs"
    certificate_root.mkdir(mode=0o700)
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=hysteria",
            "-addext",
            "subjectAltName=DNS:hysteria",
            "-keyout",
            str(certificate_root / "privkey.pem"),
            "-out",
            str(certificate_root / "fullchain.pem"),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
        timeout=20,
    )
    for path in certificate_root.iterdir():
        path.chmod(0o600)

    values = _values()
    values["hysteria"]["certificate_path"] = "/certs/fullchain.pem"  # type: ignore[index]
    values["hysteria"]["private_key_path"] = "/certs/privkey.pem"  # type: ignore[index]
    values_path = tmp_path / "values.json"
    values_path.write_text(json.dumps(values), encoding="utf-8")
    rendered = tmp_path / "rendered"
    render_runtime_configs(values_path, rendered)
    client_config = {
        "server": "hysteria:8443",
        "auth": "profile-auth-value-1234",
        "tls": {"sni": "hysteria", "insecure": True},
        "obfs": {
            "type": "salamander",
            "salamander": {"password": "test-obfs-value-1234"},
        },
        "socks5": {"listen": "0.0.0.0:1080"},
    }
    client_path = rendered / "client.yaml"
    client_path.write_text(yaml.safe_dump(client_config), encoding="utf-8")
    client_path.chmod(0o600)

    project = f"ezop-runtime-{uuid4().hex[:10]}"
    environment = dict(os.environ)
    environment.update(
        {
            "RUNTIME_CONFIG_ROOT": str(rendered),
            "RUNTIME_CERT_ROOT": str(certificate_root),
        }
    )
    compose = [
        "docker",
        "compose",
        "-f",
        str(_COMPOSE_FILE),
        "--project-name",
        project,
    ]
    try:
        _run([*compose, "up", "-d", "--pull", "always"], environment=environment)
        xray_port = _published_port(
            "xray", 10085, project=project, environment=environment
        )
        stats_port = _published_port(
            "hysteria", 9999, project=project, environment=environment
        )
        socks_port = 11080
        control_port = _published_port(
            "control", 8000, project=project, environment=environment
        )

        xray = GrpcXrayClient(
            f"127.0.0.1:{xray_port}",
            "protected-entry",
        )
        xray.wait_ready(20.0)
        assert xray.list_users() == set()
        xray.add_user(
            _RUNTIME_ID,
            UUID("11111111-1111-4111-8111-111111111111"),
        )
        assert xray.list_users() == {_RUNTIME_ID}
        xray.remove_user(_RUNTIME_ID)
        assert xray.list_users() == set()
        xray.close()

        try:
            _wait_for(lambda: _socket_ready(socks_port))
        except RuntimeError:
            raise RuntimeError(
                f"runtime client did not become ready: "
                f"{_runtime_logs(compose, environment=environment)}"
            ) from None
        try:
            _wait_for(
                lambda: _socks_request_ready(socks_port, environment=environment)
            )
        except RuntimeError:
            raise RuntimeError(
                "runtime request did not succeed; logs: "
                f"{_runtime_logs(compose, environment=environment)}"
            ) from None
        stats_url = f"http://127.0.0.1:{stats_port}"
        headers = {"Authorization": "test-stats-value-5678"}

        def online() -> bool:
            response = httpx.get(f"{stats_url}/online", headers=headers, timeout=2)
            response.raise_for_status()
            return _RUNTIME_ID in response.json()

        _wait_for(online)
        blocked = httpx.post(
            f"http://127.0.0.1:{control_port}/test/block",
            timeout=2,
        )
        blocked.raise_for_status()
        hysteria = HttpHysteriaClient(stats_url, "test-stats-value-5678")
        hysteria.kick(_RUNTIME_ID)
        hysteria.close()
        _wait_for(lambda: not online())
    finally:
        subprocess.run(
            [*compose, "down", "--volumes", "--remove-orphans"],
            cwd=_ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=60,
        )
