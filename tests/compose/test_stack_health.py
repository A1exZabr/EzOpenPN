from __future__ import annotations

import json
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest

_ROOT = Path(__file__).resolve().parents[2]
_STATE_PATH = Path(f"/tmp/ezopenpn-stack-state-{os.getuid()}.json")
_REQUIRED_ASSETS = (
    _ROOT / "tests" / "compose" / "fixtures" / "test-ip-cert.sh",
    _ROOT / "tests" / "compose" / "fixtures" / "Caddyfile.test",
    _ROOT / "tests" / "compose" / "stack-override.yaml",
    _ROOT / "tests" / "compose" / "stack-up.sh",
    _ROOT / "tests" / "compose" / "stack-down.sh",
)


def test_stack_harness_assets_are_present() -> None:
    assert all(path.is_file() for path in _REQUIRED_ASSETS)


@dataclass(frozen=True)
class StackHarness:
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
        while time.monotonic() < deadline:
            if self.health(service) == "healthy":
                return
            time.sleep(0.5)
        raise RuntimeError(f"{service} did not become healthy")

    def install_test_certificate(self) -> None:
        source = self.root / "gateway-certs"
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

    def start_hysteria(self) -> None:
        self.run("up", "-d", "hysteria", timeout=120)

    def https_get(self, path: str) -> httpx.Response:
        return httpx.get(
            f"https://127.0.0.1:9443{path}",
            verify=str(self.root / "gateway-certs" / "ca.crt"),
            timeout=10,
        )


@pytest.fixture(scope="module")
def stack() -> StackHarness:
    if not _STATE_PATH.is_file():
        pytest.skip("start the local stack harness first")
    state = json.loads(_STATE_PATH.read_text(encoding="utf-8"))
    harness = StackHarness(
        root=Path(state["root"]),
        project=state["project"],
        environment_file=Path(state["environment_file"]),
    )
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
