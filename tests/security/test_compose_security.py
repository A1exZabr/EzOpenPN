from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "deploy/compose.yaml"
ENVIRONMENT = ROOT / "tests/compose/fixtures/stack.env"
VARIABLE = re.compile(r"\$\{([A-Z][A-Z0-9_]*)(?::\?[^}]*)?\}")
ALLOWED_BIND_ROOTS = ("/etc/ezopenpn/", "/var/lib/ezopenpn/")


def _compose() -> dict[str, object]:
    values = dict(
        line.split("=", 1)
        for line in ENVIRONMENT.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    )
    rendered = VARIABLE.sub(lambda match: values[match.group(1)], COMPOSE.read_text())
    loaded = yaml.safe_load(rendered)
    assert isinstance(loaded, dict)
    return loaded


def test_compose_has_no_secret_environment_or_labels() -> None:
    services = _compose()["services"]
    assert isinstance(services, dict)
    for service in services.values():
        assert isinstance(service, dict)
        assert service.get("environment", {}) == {}
        assert service.get("env_file", []) == []
        assert service.get("labels", {}) == {}
        assert "docker.sock" not in json.dumps(service)


def test_every_bind_mount_is_inside_an_allowlisted_root() -> None:
    services = _compose()["services"]
    assert isinstance(services, dict)
    for service in services.values():
        assert isinstance(service, dict)
        for mount in service.get("volumes", []):
            assert mount["type"] == "bind"
            assert str(mount["source"]).startswith(ALLOWED_BIND_ROOTS)
            assert mount["bind"] == {"create_host_path": False}


def test_publication_is_never_triggered_by_push() -> None:
    workflow_paths = sorted((ROOT / ".github/workflows").glob("*.yml"))
    for path in workflow_paths:
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert isinstance(workflow, dict)
        if path.name in {"images.yml", "release.yml"}:
            triggers = workflow.get("on", workflow.get(True, {}))
            assert isinstance(triggers, dict)
            assert "push" not in triggers
