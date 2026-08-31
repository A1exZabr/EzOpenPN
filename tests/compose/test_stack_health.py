from __future__ import annotations

import json
import os
import ssl
import subprocess
import time
from base64 import urlsafe_b64encode
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar
from uuid import uuid4

import httpx
import pytest

_ROOT = Path(__file__).resolve().parents[2]
_STATE_PATH = Path(f"/tmp/ezopenpn-stack-state-{os.getuid()}.json")
_REQUIRED_ASSETS = (
    _ROOT / "tests" / "compose" / "fixtures" / "test-ip-cert.sh",
    _ROOT / "tests" / "compose" / "fixtures" / "Caddyfile.test",
    _ROOT / "tests" / "compose" / "stack-override.yaml",
    _ROOT / "tests" / "compose" / "project-name.sh",
    _ROOT / "tests" / "compose" / "stack-up.sh",
    _ROOT / "tests" / "compose" / "stack-down.sh",
)


def test_stack_harness_assets_are_present() -> None:
    assert all(path.is_file() for path in _REQUIRED_ASSETS)


def test_stack_project_name_normalizes_mixed_case_suffix() -> None:
    result = subprocess.run(
        [
            "bash",
            str(_ROOT / "tests" / "compose" / "project-name.sh"),
            "/tmp/ezopenpn-stack.aB9xYz",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == "ezop-stack-ab9xyz"


@dataclass(frozen=True)
class StackHarness:
    services: ClassVar[tuple[str, ...]] = (
        "control",
        "xray",
        "hysteria",
        "gateway",
        "cert-sync",
    )

    root: Path
    project: str
    environment_file: Path

    @property
    def compose(self) -> list[str]:
        return [
            "docker",
            "compose",
            "--env-file",
            str(self.environment_file),
            "-f",
            str(_ROOT / "deploy" / "compose.yaml"),
            "-f",
            str(_ROOT / "tests" / "compose" / "stack-override.yaml"),
            "--project-name",
            self.project,
        ]

    def run(self, *arguments: str, timeout: int = 120) -> str:
        result = subprocess.run(
            [*self.compose, *arguments],
            cwd=_ROOT,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
        if result.returncode != 0:
            diagnostic = (result.stdout + result.stderr).strip()[-2000:]
            raise RuntimeError(f"stack command failed: {diagnostic}")
        return result.stdout.strip()

    def start_without_certificate(self) -> None:
        self.run("up", "-d", "xray", "control", "gateway", "cert-sync", timeout=240)

    def container_id(self, service: str) -> str:
        return self.run("ps", "-q", service)

    def inspect(self, service: str) -> dict[str, object]:
        container_id = self.container_id(service)
        if not container_id:
            raise RuntimeError(f"{service} container is missing")
        result = subprocess.run(
            ["docker", "inspect", container_id],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
            timeout=20,
        )
        if result.returncode != 0:
            diagnostic = (result.stdout + result.stderr).strip()[-1200:]
            raise RuntimeError(f"cannot inspect {service}: {diagnostic}")
        payload = json.loads(result.stdout)
        if not isinstance(payload, list) or len(payload) != 1:
            raise RuntimeError(f"unexpected inspection result for {service}")
        inspection = payload[0]
        if not isinstance(inspection, dict):
            raise RuntimeError(f"unexpected inspection object for {service}")
        return inspection

    def health(self, service: str) -> str:
        container_id = self.container_id(service)
        if not container_id:
            return "missing"
        result = subprocess.run(
            [
                "docker",
                "inspect",
                "--format",
                "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}",
                container_id,
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
            timeout=20,
        )
        return result.stdout.strip() if result.returncode == 0 else "missing"

    def wait_healthy(self, service: str, *, timeout: float = 60) -> None:
        deadline = time.monotonic() + timeout
        latest = "missing"
        while time.monotonic() < deadline:
            latest = self.health(service)
            if latest == "healthy":
                return
            time.sleep(0.5)
        status = self.run("ps", "--all")[-1600:]
        logs = self.run("logs", "--no-color", "--tail", "60", service)[-2400:]
        raise RuntimeError(
            f"{service} did not become healthy; health={latest}; "
            f"status={status}; logs={logs}"
        )

    def install_test_certificate(self) -> None:
        source = self.root / "gateway-certs"
        self._install_gateway_certificate(source)

    def _install_gateway_certificate(self, source: Path) -> None:
        destination = self.root / "caddy-data" / "certificates" / "test"
        subprocess.run(
            ["sudo", "mkdir", "-p", str(destination)],
            stdin=subprocess.DEVNULL,
            check=True,
            timeout=20,
        )
        for source_name, destination_name in (
            ("server.crt", "127.0.0.1.crt"),
            ("server.key", "127.0.0.1.key"),
        ):
            subprocess.run(
                [
                    "sudo",
                    "install",
                    "-o",
                    "10004",
                    "-g",
                    "11003",
                    "-m",
                    "0600",
                    str(source / source_name),
                    str(destination / destination_name),
                ],
                stdin=subprocess.DEVNULL,
                check=True,
                timeout=20,
            )

    def install_rotated_test_certificate(self) -> Path:
        source = self.root / "rotated-gateway-certs"
        subprocess.run(
            [
                "bash",
                str(_ROOT / "tests" / "compose" / "fixtures" / "test-ip-cert.sh"),
                str(source),
                "127.0.0.1",
                "2",
            ],
            cwd=_ROOT,
            stdin=subprocess.DEVNULL,
            check=True,
            timeout=30,
        )
        self._install_gateway_certificate(source)
        return source / "ca.crt"

    def exported_leaf_fingerprint(self) -> str:
        certificate_path = self.root / "hysteria-certs" / "fullchain.pem"
        privilege_prefix = [] if os.geteuid() == 0 else ["sudo", "-n"]
        result = subprocess.run(
            [
                *privilege_prefix,
                "openssl",
                "x509",
                "-in",
                str(certificate_path),
                "-noout",
                "-fingerprint",
                "-sha256",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        if result.returncode != 0:
            raise ValueError("exported certificate cannot be inspected")
        fingerprint = result.stdout.strip().partition("=")[2].replace(":", "").lower()
        if len(fingerprint) != 64 or any(
            character not in "0123456789abcdef" for character in fingerprint
        ):
            raise ValueError("certificate fingerprint is invalid")
        return fingerprint

    def wait_for_new_export(self, previous: str, *, timeout: float = 15) -> str:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                current = self.exported_leaf_fingerprint()
            except (OSError, ValueError):
                current = previous
            if current != previous:
                return current
            time.sleep(0.25)
        raise RuntimeError("rotated certificate was not exported")

    def start_hysteria(self) -> None:
        self.run("up", "-d", "hysteria", timeout=120)

    def https_get(self, path: str) -> httpx.Response:
        context = ssl.create_default_context(
            cafile=str(self.root / "gateway-certs" / "ca.crt")
        )
        try:
            return httpx.get(
                f"https://127.0.0.1:9443{path}",
                verify=context,
                timeout=10,
            )
        except httpx.HTTPError as error:
            logs = self.run("logs", "--no-color", "--tail", "80", "gateway")[-3000:]
            raise RuntimeError(f"panel request failed: {error}; gateway logs={logs}") from error

    def _environment_value(self, name: str) -> str:
        prefix = f"{name}="
        for line in self.environment_file.read_text(encoding="utf-8").splitlines():
            if line.startswith(prefix):
                return line.removeprefix(prefix)
        raise RuntimeError(f"{name} is missing from the stack environment")

    @staticmethod
    def _read_protected_bytes(path: Path) -> bytes:
        privilege_prefix = [] if os.geteuid() == 0 else ["sudo", "-n"]
        result = subprocess.run(
            [*privilege_prefix, "cat", str(path)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=10,
        )
        if result.returncode != 0:
            raise RuntimeError("protected test material cannot be read")
        return result.stdout

    def verify_hysteria_handshake(self, ca_path: Path) -> None:
        auth = (self.root / "test-client-auth").read_text(encoding="ascii")
        obfs = urlsafe_b64encode(
            self._read_protected_bytes(
                self.root / "secrets" / "hysteria-obfs.key"
            )
        ).rstrip(b"=").decode("ascii")
        config_path = self.root / "rotation-client.yaml"
        config_path.write_text(
            "\n".join(
                (
                    'server: "hysteria:8443"',
                    f'auth: "{auth}"',
                    "tls:",
                    '  sni: "127.0.0.1"',
                    "  insecure: false",
                    '  ca: "/test-ca/ca.crt"',
                    "obfs:",
                    "  type: salamander",
                    "  salamander:",
                    f'    password: "{obfs}"',
                    "socks5:",
                    '  listen: "0.0.0.0:1080"',
                    "",
                )
            ),
            encoding="utf-8",
        )
        config_path.chmod(0o600)
        client_name = f"{self.project}-rotation-{uuid4().hex[:8]}"
        command = [
            "docker",
            "run",
            "--detach",
            "--name",
            client_name,
            "--label",
            f"com.ezopenpn.stack-test={self.project}",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "--network",
            f"{self.project}_backend",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--read-only",
            "--mount",
            f"type=bind,src={config_path},dst=/etc/hysteria-client.yaml,readonly",
            "--mount",
            f"type=bind,src={ca_path},dst=/test-ca/ca.crt,readonly",
            self._environment_value("HYSTERIA_IMAGE"),
            "client",
            "-c",
            "/etc/hysteria-client.yaml",
            "--disable-update-check",
        ]
        subprocess.run(command, check=True, capture_output=True, text=True, timeout=30)
        diagnostic = "client did not become ready"
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                status = subprocess.run(
                    ["docker", "inspect", "--format", "{{.State.Status}}", client_name],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=10,
                ).stdout.strip()
                if status != "running":
                    diagnostic = f"client stopped with state {status or 'missing'}"
                    break
                logs = subprocess.run(
                    ["docker", "logs", "--tail", "30", client_name],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=10,
                )
                output = logs.stdout + logs.stderr
                if (
                    "connected to server" in output
                    and "SOCKS5 server listening" in output
                ):
                    return
                time.sleep(0.25)
            logs = subprocess.run(
                ["docker", "logs", "--tail", "30", client_name],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            sanitized = (logs.stdout + logs.stderr).replace(auth, "<redacted>").replace(
                obfs, "<redacted>"
            )
            diagnostic = f"{diagnostic}: {sanitized.strip()[-1200:]}"
        finally:
            subprocess.run(
                ["docker", "stop", "--time", "2", client_name],
                capture_output=True,
                check=False,
                timeout=15,
            )
            subprocess.run(
                ["docker", "rm", client_name],
                capture_output=True,
                check=False,
                timeout=15,
            )
        raise RuntimeError(diagnostic)


def prepared_stack_harness() -> StackHarness:
    if not _STATE_PATH.is_file():
        pytest.skip("start the local stack harness first")
    state = json.loads(_STATE_PATH.read_text(encoding="utf-8"))
    return StackHarness(
        root=Path(state["root"]),
        project=state["project"],
        environment_file=Path(state["environment_file"]),
    )


@pytest.fixture(scope="module")
def stack() -> StackHarness:
    harness = prepared_stack_harness()
    harness.start_without_certificate()
    yield harness


@pytest.mark.integration
def test_hysteria_waits_for_exported_certificate(stack: StackHarness) -> None:
    stack.wait_healthy("gateway")
    assert stack.health("cert-sync") != "healthy"
    assert stack.health("hysteria") != "healthy"

    stack.install_test_certificate()
    stack.wait_healthy("cert-sync", timeout=20)
    stack.start_hysteria()
    stack.wait_healthy("hysteria", timeout=30)


@pytest.mark.integration
def test_panel_headers_are_present(stack: StackHarness) -> None:
    response = stack.https_get("/login")
    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]

    internal = stack.https_get("/internal/hysteria/auth")
    assert internal.status_code == 404
