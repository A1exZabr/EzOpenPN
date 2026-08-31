from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
from tests.compose.test_stack_health import StackHarness, prepared_stack_harness

_ROOT = Path(__file__).resolve().parents[2]
_SCAN_SCRIPT = _ROOT / "tests" / "compose" / "scan_ports.sh"


def _write_fake_nmap(path: Path, *, unexpected_tcp_port: int | None = None) -> None:
    tcp_ports = [22, 80, 443, 9443]
    if unexpected_tcp_port is not None:
        tcp_ports.append(unexpected_tcp_port)
    tcp_xml = "".join(
        f'<port protocol="tcp" portid="{port}"><state state="open"/></port>'
        for port in tcp_ports
    )
    udp_xml = (
        '<nmaprun><host><ports><port protocol="udp" portid="443">'
        '<state state="open|filtered"/></port></ports></host></nmaprun>'
    )
    script = f"""#!/usr/bin/env bash
set -euo pipefail
if [[ " $* " == *" -sU "* ]]; then
  printf '%s\\n' '{udp_xml}'
else
  printf '%s\\n' '<nmaprun><host><ports>{tcp_xml}</ports></host></nmaprun>'
fi
"""
    path.write_text(script, encoding="utf-8")
    path.chmod(0o700)


def _run_scan(
    fake_nmap: Path, *, host: str = "127.0.0.1"
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["NMAP_BIN"] = str(fake_nmap)
    return subprocess.run(
        ["bash", str(_SCAN_SCRIPT), host, "22"],
        cwd=_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )


def test_port_scan_reports_exact_allowed_set(tmp_path: Path) -> None:
    fake_nmap = tmp_path / "nmap"
    _write_fake_nmap(fake_nmap)
    result = _run_scan(fake_nmap)

    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["ok"] is True
    assert report["observed"] == {
        "tcp": [22, 80, 443, 9443],
        "udp": [443],
    }
    assert report["unexpected"] == {"tcp": [], "udp": []}
    assert report["missing"] == {"tcp": [], "udp": []}


def test_port_scan_rejects_an_unexpected_listener(tmp_path: Path) -> None:
    fake_nmap = tmp_path / "nmap"
    _write_fake_nmap(fake_nmap, unexpected_tcp_port=8000)
    result = _run_scan(fake_nmap)

    assert result.returncode == 1
    report = json.loads(result.stdout)
    assert report["ok"] is False
    assert report["unexpected"]["tcp"] == [8000]


def test_remote_filtered_udp_is_not_reported_as_an_open_listener(
    tmp_path: Path,
) -> None:
    fake_nmap = tmp_path / "nmap"
    _write_fake_nmap(fake_nmap)
    result = _run_scan(fake_nmap, host="203.0.113.10")

    assert result.returncode == 1
    report = json.loads(result.stdout)
    assert report["observed"]["udp"] == []
    assert report["uncertain"]["udp"] == [443]
    assert report["missing"]["udp"] == [443]


def test_stack_harness_exposes_runtime_inspection_interface() -> None:
    assert StackHarness.services == (
        "control",
        "xray",
        "hysteria",
        "gateway",
        "cert-sync",
    )
    assert callable(StackHarness.inspect)


@pytest.fixture(scope="module")
def running_stack() -> StackHarness:
    stack = prepared_stack_harness()
    stack.start_without_certificate()
    if stack.health("cert-sync") != "healthy":
        stack.install_test_certificate()
        stack.wait_healthy("cert-sync", timeout=20)
    if stack.health("hysteria") != "healthy":
        stack.start_hysteria()
        stack.wait_healthy("hysteria", timeout=30)
    return stack


@pytest.mark.integration
def test_runtime_container_hardening(running_stack: StackHarness) -> None:
    for service in running_stack.services:
        inspection = running_stack.inspect(service)
        host = inspection["HostConfig"]
        assert host["Privileged"] is False
        assert host["ReadonlyRootfs"] is True
        assert host["CapAdd"] in (None, [])
        assert host["CapDrop"] == ["ALL"]
        assert "no-new-privileges:true" in host["SecurityOpt"]
        assert host["PidsLimit"] == 128
        assert host["Memory"] > 0
        assert "/var/run/docker.sock" not in {
            mount["Source"] for mount in inspection["Mounts"]
        }

    assert running_stack.inspect("cert-sync")["HostConfig"]["NetworkMode"] == "none"


@pytest.mark.integration
def test_runtime_publishes_only_documented_ports(running_stack: StackHarness) -> None:
    published: set[tuple[str, str, str, str]] = set()
    for service in running_stack.services:
        inspection = running_stack.inspect(service)
        bindings = inspection["HostConfig"]["PortBindings"] or {}
        for container_port, host_bindings in bindings.items():
            for binding in host_bindings:
                published.add(
                    (
                        service,
                        container_port,
                        binding["HostIp"],
                        binding["HostPort"],
                    )
                )

    assert published == {
        ("gateway", "8080/tcp", "127.0.0.1", "80"),
        ("gateway", "9443/tcp", "127.0.0.1", "9443"),
        ("hysteria", "8443/udp", "127.0.0.1", "443"),
        ("xray", "8443/tcp", "127.0.0.1", "443"),
    }
