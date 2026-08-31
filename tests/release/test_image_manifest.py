from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests/release/fixtures/images.release.json"
SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
HEX_SHA256 = re.compile(r"[0-9a-f]{64}")


def _manifest() -> dict[str, object]:
    loaded = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def test_release_image_manifest_has_attested_digest() -> None:
    manifest = _manifest()
    source = manifest["source"]
    assert isinstance(source, dict)
    assert source["repository"] == "A1exZabr/EzOpenPN"
    assert re.fullmatch(r"[0-9a-f]{40}", str(source["commit"]))

    images = manifest["images"]
    assert isinstance(images, list)
    assert {image["name"] for image in images} == {
        "control",
        "xray",
        "gateway",
        "cert-sync",
    }
    for image in images:
        assert isinstance(image, dict)
        reference = image["reference"]
        digest = image["digest"]
        assert isinstance(reference, str)
        assert reference == f"ghcr.io/a1exzabr/ezopenpn-{image['name']}"
        assert SHA256.fullmatch(str(digest))
        assert HEX_SHA256.fullmatch(str(image["sbom_sha256"]))
        assert image["sbom_path"] == f"{image['name']}.spdx.json"
        assert image["provenance_subject"] == f"{reference}@{digest}"
        assert str(image["workflow_identity"]).startswith(
            "https://github.com/A1exZabr/EzOpenPN/.github/workflows/images.yml@refs/"
        )


def test_image_workflow_is_manual_and_never_writes_latest() -> None:
    workflow = (ROOT / ".github/workflows/images.yml").read_text(encoding="utf-8")
    assert "workflow_dispatch:" in workflow
    assert "\n  push:" not in workflow
    assert ":latest" not in workflow
    assert "attest-build-provenance" in workflow
    assert "attest-sbom" in workflow
    assert "cosign sign" in workflow
    assert "dockerfile: runtime/Dockerfile.gateway" in workflow
