from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml

_ROOT = Path(__file__).resolve().parents[2]
_COMPOSE_PATH = _ROOT / "deploy" / "compose.yaml"
_ENV_PATH = _ROOT / "tests" / "compose" / "fixtures" / "stack.env"
_VARIABLE = re.compile(r"\$\{([A-Z][A-Z0-9_]*)(?::\?[^}]*)?\}")


def _environment() -> dict[str, str]:
    result: dict[str, str] = {}
    for line in _ENV_PATH.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#"):
            name, value = line.split("=", 1)
            result[name] = value
    return result


@pytest.fixture(scope="module")
def compose() -> dict[str, object]:
    source = _COMPOSE_PATH.read_text(encoding="utf-8")
    environment = _environment()
    rendered = _VARIABLE.sub(lambda match: environment[match.group(1)], source)
    loaded = yaml.safe_load(rendered)
    assert isinstance(loaded, dict)
    return loaded


def _services(compose: dict[str, object]) -> dict[str, dict[str, object]]:
    services = compose["services"]
    assert isinstance(services, dict)
    return services


def test_stack_contains_only_expected_services(compose: dict[str, object]) -> None:
    assert set(_services(compose)) == {
        "cert-sync",
        "control",
        "gateway",
        "hysteria",
        "xray",
    }


def test_only_expected_host_ports_are_published(compose: dict[str, object]) -> None:
    published: set[tuple[int, str]] = set()
    for service in _services(compose).values():
        for binding in service.get("ports", []):
            assert isinstance(binding, dict)
            published.add((int(binding["published"]), binding.get("protocol", "tcp")))
    assert published == {(80, "tcp"), (443, "tcp"), (443, "udp"), (9443, "tcp")}


def test_every_host_port_binds_only_public_ipv4(compose: dict[str, object]) -> None:
    for service in _services(compose).values():
        for binding in service.get("ports", []):
            assert binding["host_ip"] == "203.0.113.10"


def test_no_service_has_broad_host_control(compose: dict[str, object]) -> None:
    for service in _services(compose).values():
        serialized = json.dumps(service)
        assert service.get("privileged") is not True
        assert service.get("network_mode") not in {"host", "service:docker"}
        assert "/var/run/docker.sock" not in serialized
        assert service.get("cap_add", []) == []
        assert service.get("cap_drop") == ["ALL"]
        assert service.get("read_only") is True
        assert service.get("security_opt") == ["no-new-privileges:true"]


def test_services_are_resource_bounded_and_observable(
    compose: dict[str, object],
) -> None:
    for service in _services(compose).values():
        assert int(service["pids_limit"]) > 0
        assert service["mem_limit"]
        assert service["healthcheck"]
        assert service["logging"] == {
            "driver": "json-file",
            "options": {"max-file": "3", "max-size": "10m"},
        }


def test_network_boundaries_match_policy(compose: dict[str, object]) -> None:
    networks = compose["networks"]
    assert set(networks) == {"backend", "edge"}
    assert networks["backend"]["internal"] is True

    services = _services(compose)
    assert services["cert-sync"]["network_mode"] == "none"
    assert set(services["control"]["networks"]) == {"backend"}
    assert set(services["gateway"]["networks"]) == {"backend", "edge"}
    assert set(services["xray"]["networks"]) == {"backend", "edge"}
    assert set(services["hysteria"]["networks"]) == {"backend", "edge"}


def test_hysteria_waits_for_control_and_certificate_health(
    compose: dict[str, object],
) -> None:
    dependencies = _services(compose)["hysteria"]["depends_on"]
    assert dependencies["control"]["condition"] == "service_healthy"
    assert dependencies["cert-sync"]["condition"] == "service_healthy"


def test_all_container_users_are_numeric(compose: dict[str, object]) -> None:
    for service in _services(compose).values():
        user, group = str(service["user"]).split(":", 1)
        assert user.isdecimal()
        assert group.isdecimal()
