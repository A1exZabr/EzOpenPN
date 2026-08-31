from __future__ import annotations

import importlib.util
import re
import sys
import tomllib
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
EXPECTED_SYSTEMS = {
    "ubuntu-22.04",
    "ubuntu-24.04",
    "debian-12",
    "debian-13",
}
EXPECTED_STEPS = {
    "install": "pass",
    "rerun": "pass",
    "reset": "pass",
    "backup_restore": "pass",
    "reinstall": "pass",
    "uninstall": "pass",
}


def _runner_module() -> ModuleType:
    path = ROOT / "tests/vm/runner.py"
    specification = importlib.util.spec_from_file_location("ezopenpn_vm_runner", path)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


def test_vm_matrix_is_complete_and_locked() -> None:
    matrix = tomllib.loads(
        (ROOT / "tests/vm/matrix.toml").read_text(encoding="utf-8")
    )
    assert matrix["schema"] == 1
    assert set(matrix["images"]) == EXPECTED_SYSTEMS
    for image in matrix["images"].values():
        assert image["url"].startswith("https://")
        assert image["manifest_url"].startswith("https://")
        assert re.fullmatch(r"[0-9a-f]{64}", image["sha256"])
        assert image["manifest_algorithm"] in {"sha256", "sha512"}
        expected_length = 64 if image["manifest_algorithm"] == "sha256" else 128
        assert re.fullmatch(
            rf"[0-9a-f]{{{expected_length}}}", image["manifest_checksum"]
        )
        assert image["url"].endswith(image["filename"])


def test_vm_result_requires_every_recovery_operation() -> None:
    runner = _runner_module()
    result = {
        "schema": 1,
        "system": "ubuntu-24.04",
        "image_sha256": "a" * 64,
        "started_at": "2026-08-31T10:00:00Z",
        "finished_at": "2026-08-31T10:20:00Z",
        "steps": EXPECTED_STEPS,
        "limitations": [
            "public_certificate_not_tested",
            "external_transport_performance_not_tested",
        ],
    }

    assert runner.validate_result(result) == result


def test_cloud_init_uses_keys_only_and_disables_root_login() -> None:
    cloud_init = (ROOT / "tests/vm/cloud-init.yaml").read_text(encoding="utf-8")
    assert "@@SSH_PUBLIC_KEY@@" in cloud_init
    assert "ssh_pwauth: false" in cloud_init
    assert "disable_root: true" in cloud_init
    assert "plain_text_passwd" not in cloud_init
    assert "lock_passwd: true" in cloud_init


def test_vm_workflow_is_manual_and_runs_every_system() -> None:
    workflow = (ROOT / ".github/workflows/vm-matrix.yml").read_text(encoding="utf-8")
    assert "workflow_dispatch:" in workflow
    assert "images_run_id:" in workflow
    assert "/dev/kvm" in workflow
    assert "tests/vm/runner.py" in workflow
    for system in EXPECTED_SYSTEMS:
        assert system in workflow


def test_vm_failure_diagnostics_capture_sanitized_service_evidence(
    monkeypatch: Any,
) -> None:
    runner = _runner_module()
    calls: list[tuple[str, dict[str, Any]]] = []

    def fake_ssh(
        _key: Path,
        _port: int,
        remote_command: str,
        **kwargs: Any,
    ) -> str:
        calls.append((remote_command, kwargs))
        return ""

    monkeypatch.setattr(runner, "_ssh", fake_ssh)

    runner._collect_failure_diagnostics(Path("/tmp/key"), 22022, ("registry-secret",))

    assert len(calls) == 1
    command, kwargs = calls[0]
    assert "for service in control xray hysteria gateway cert-sync" in command
    assert 'ezopenpn logs "$service"' in command
    assert "docker inspect" in command
    assert "table {{.Names}}" in command
    assert "docker compose config" not in command
    assert kwargs["secrets_to_redact"] == ("registry-secret",)
    assert kwargs["print_output"] is True


def test_interactive_runner_answers_only_after_each_prompt(capsys: Any) -> None:
    runner = _runner_module()
    script = (
        "import sys;"
        "sys.stdout.write('Login: ');sys.stdout.flush();"
        "login=sys.stdin.readline().strip();"
        "sys.stdout.write('Password: ');sys.stdout.flush();"
        "password=sys.stdin.readline().strip();"
        "print('accepted='+login+':'+password)"
    )

    output = runner._run_interactive(
        [sys.executable, "-c", script],
        label="interactive fixture",
        interactions=(("Login: ", "owner"), ("Password: ", "secret-value")),
        timeout=5,
        secrets_to_redact=("secret-value",),
    )

    assert "accepted=owner:[redacted]" in output
    assert "secret-value" not in output
    assert "secret-value" not in capsys.readouterr().out


def test_interactive_timeout_keeps_redacted_partial_output() -> None:
    runner = _runner_module()
    script = (
        "import sys,time;"
        "sys.stdout.write('waiting secret-value');sys.stdout.flush();"
        "time.sleep(5)"
    )

    with pytest.raises(
        runner.VmRunError,
        match=r"(?s)timed out.*waiting \[redacted\]",
    ):
        runner._run_interactive(
            [sys.executable, "-c", script],
            label="stalled fixture",
            interactions=(),
            timeout=1,
            secrets_to_redact=("secret-value",),
            print_output=False,
        )
