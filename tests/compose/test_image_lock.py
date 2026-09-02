from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_EXPECTED_IMAGES = {
    "caddy",
    "distroless-base",
    "go-builder",
    "hysteria",
    "python-base",
    "xray-upstream",
}
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


@pytest.fixture(scope="module")
def image_sources() -> dict[str, dict[str, str]]:
    path = _ROOT / "deploy" / "images.toml"
    return tomllib.loads(path.read_text(encoding="utf-8"))["images"]


@pytest.fixture(scope="module")
def image_lock() -> dict[str, dict[str, str]]:
    path = _ROOT / "deploy" / "images.lock"
    return tomllib.loads(path.read_text(encoding="utf-8"))["images"]


def test_every_production_image_has_amd64_digest(
    image_lock: dict[str, dict[str, str]],
) -> None:
    assert set(image_lock) == _EXPECTED_IMAGES
    for image in image_lock.values():
        assert _DIGEST.fullmatch(image["digest"])
        assert image["platform"] == "linux/amd64"


def test_lock_matches_declared_sources(
    image_sources: dict[str, dict[str, str]],
    image_lock: dict[str, dict[str, str]],
) -> None:
    assert set(image_sources) == _EXPECTED_IMAGES
    for name, source in image_sources.items():
        assert image_lock[name]["repository"] == source["repository"]
        assert image_lock[name]["version"] == source["version"]


def test_runtime_dockerfiles_use_only_locked_build_arguments() -> None:
    for relative in (
        "runtime/Dockerfile.xray",
        "runtime/Dockerfile.hysteria",
        "runtime/Dockerfile.cert-sync",
        "runtime/Dockerfile.gateway",
    ):
        dockerfile = (_ROOT / relative).read_text(encoding="utf-8")
        from_lines = [
            line for line in dockerfile.splitlines() if line.startswith("FROM ")
        ]
        assert from_lines
        assert all("${" in line and "@${" in line for line in from_lines)


def test_final_runtime_images_are_non_root() -> None:
    expected_users = {
        "runtime/Dockerfile.xray": "USER 10002:11001",
        "runtime/Dockerfile.cert-sync": "USER 10004:11003",
        "runtime/Dockerfile.gateway": "USER 10004:11003",
    }
    for relative, user in expected_users.items():
        dockerfile = (_ROOT / relative).read_text(encoding="utf-8")
        assert user in dockerfile


def test_gateway_image_removes_unneeded_file_capability() -> None:
    dockerfile = (_ROOT / "runtime" / "Dockerfile.gateway").read_text(encoding="utf-8")
    assert "setcap -r /usr/bin/caddy" in dockerfile


def test_gateway_source_and_security_refresh_are_immutable() -> None:
    lock = tomllib.loads(
        (_ROOT / "runtime/caddy-source.lock").read_text(encoding="utf-8")
    )
    dockerfile = (_ROOT / "runtime/Dockerfile.gateway").read_text(encoding="utf-8")
    assert lock["version"] == "2.11.4"
    assert re.fullmatch(r"[0-9a-f]{40}", lock["commit"])
    assert re.fullmatch(r"[0-9a-f]{64}", lock["sha256"])
    assert lock["url"].startswith(
        "https://github.com/caddyserver/caddy/releases/download/"
    )
    assert lock["url"] in dockerfile
    assert f"sha256:{lock['sha256']}" in dockerfile
    assert "COPY --from=builder /out/caddy /usr/bin/caddy" in dockerfile
    for name, version in lock["modules"].items():
        assert f"{name}@{version}" in dockerfile


def test_runtime_images_use_grpc_with_cve_2026_84304_fixed() -> None:
    for relative in ("runtime/caddy-source.lock", "runtime/xray-source.lock"):
        lock = tomllib.loads((_ROOT / relative).read_text(encoding="utf-8"))
        assert lock["modules"]["google.golang.org/grpc"] == "v1.83.1"


def test_gateway_uses_crypto_with_cve_2026_56854_fixed() -> None:
    lock = tomllib.loads(
        (_ROOT / "runtime/caddy-source.lock").read_text(encoding="utf-8")
    )
    assert lock["modules"]["golang.org/x/crypto"] == "v0.55.0"


def test_gateway_security_refresh_uses_compatible_module_set() -> None:
    gateway = tomllib.loads(
        (_ROOT / "runtime/caddy-source.lock").read_text(encoding="utf-8")
    )["modules"]
    xray = tomllib.loads(
        (_ROOT / "runtime/xray-source.lock").read_text(encoding="utf-8")
    )["modules"]
    for name in (
        "golang.org/x/crypto",
        "golang.org/x/net",
        "golang.org/x/text",
        "google.golang.org/grpc",
    ):
        assert gateway[name] == xray[name]


def test_xray_source_and_security_refresh_are_immutable() -> None:
    lock = tomllib.loads(
        (_ROOT / "runtime/xray-source.lock").read_text(encoding="utf-8")
    )
    dockerfile = (_ROOT / "runtime/Dockerfile.xray").read_text(encoding="utf-8")
    module = (_ROOT / "runtime/xray-patched.mod").read_text(encoding="utf-8")
    assert lock["version"] == "26.3.27"
    assert re.fullmatch(r"[0-9a-f]{40}", lock["commit"])
    assert re.fullmatch(r"[0-9a-f]{64}", lock["sha256"])
    assert lock["url"].startswith("https://github.com/XTLS/Xray-core/archive/")
    assert lock["url"] in dockerfile
    assert f"sha256:{lock['sha256']}" in dockerfile
    assert "COPY --from=xray-upstream /usr/local/bin/xray" not in dockerfile
    for name, version in lock["modules"].items():
        assert f"{name} {version}" in module
