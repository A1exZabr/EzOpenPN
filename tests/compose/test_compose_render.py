from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_COMPOSE_PATH = _ROOT / "deploy" / "compose.yaml"
_ENV_PATH = _ROOT / "tests" / "compose" / "fixtures" / "stack.env"


def _docker_compose_available() -> bool:
    if shutil.which("docker") is None:
        return False
    return (
        subprocess.run(
            ["docker", "compose", "version"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=10,
        ).returncode
        == 0
    )


@pytest.fixture(scope="module")
def rendered_compose() -> dict[str, object]:
    if not _docker_compose_available():
        pytest.skip("Docker Compose is unavailable")
    result = subprocess.run(
        [
            "docker",
            "compose",
            "--env-file",
            str(_ENV_PATH),
            "-f",
            str(_COMPOSE_PATH),
            "config",
            "--format",
            "json",
        ],
        cwd=_ROOT,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if result.returncode != 0:
        pytest.fail(f"Compose rendering failed: {result.stderr.strip()[-1000:]}")
    loaded = json.loads(result.stdout)
    assert isinstance(loaded, dict)
    return loaded


def test_rendered_compose_has_only_digest_references(
    rendered_compose: dict[str, object],
) -> None:
    services = rendered_compose["services"]
    for service in services.values():
        assert "@sha256:" in service["image"]


def test_rendered_compose_has_no_unresolved_variables(
    rendered_compose: dict[str, object],
) -> None:
    assert "${" not in json.dumps(rendered_compose)
