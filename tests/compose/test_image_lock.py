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
    for relative in ("runtime/Dockerfile.xray", "runtime/Dockerfile.cert-sync"):
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
    }
    for relative, user in expected_users.items():
        dockerfile = (_ROOT / relative).read_text(encoding="utf-8")
        assert user in dockerfile
