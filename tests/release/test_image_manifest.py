from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
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
        "hysteria",
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
    assert "cosign sign" in workflow
    assert "cosign attest" in workflow
    assert "--type slsaprovenance1" in workflow
    assert "--type spdxjson" in workflow
    assert "attest-build-provenance" not in workflow
    assert "attest-sbom" not in workflow
    assert "dockerfile: runtime/Dockerfile.gateway" in workflow
    assert "dockerfile: runtime/Dockerfile.hysteria" in workflow


def test_image_verifier_checks_both_private_registry_attestations() -> None:
    verifier = (ROOT / "tools/verify_image_attestations.sh").read_text(
        encoding="utf-8"
    )
    assert "cosign verify-attestation" in verifier
    assert "--type slsaprovenance1" in verifier
    assert "--type spdxjson" in verifier
    assert "gh attestation verify" not in verifier


def test_image_verifier_binds_registry_attestations_to_local_evidence(
    tmp_path: Path,
) -> None:
    sbom_dir = tmp_path / "sbom"
    provenance_dir = tmp_path / "provenance"
    cosign_data = tmp_path / "cosign-data"
    fake_bin = tmp_path / "bin"
    for directory in (sbom_dir, provenance_dir, cosign_data, fake_bin):
        directory.mkdir()

    fake_cosign = fake_bin / "cosign"
    fake_cosign.write_text(
        """#!/usr/bin/env python3
import os
import sys
from pathlib import Path

arguments = sys.argv[1:]
if arguments[0] == "verify":
    raise SystemExit(0)
if arguments[0] != "verify-attestation":
    raise SystemExit(2)
kind = arguments[arguments.index("--type") + 1]
subject = arguments[-1]
name = subject.split("ezopenpn-", 1)[1].split("@", 1)[0]
print((Path(os.environ["FAKE_COSIGN_DATA"]) / f"{name}.{kind}.json").read_text())
""",
        encoding="utf-8",
    )
    fake_cosign.chmod(0o755)

    commit = "0123456789abcdef0123456789abcdef01234567"
    identity = (
        "https://github.com/A1exZabr/EzOpenPN/.github/workflows/"
        "images.yml@refs/heads/main"
    )
    dockerfiles = {
        "cert-sync": "runtime/Dockerfile.cert-sync",
        "control": "control/Dockerfile",
        "gateway": "runtime/Dockerfile.gateway",
        "hysteria": "runtime/Dockerfile.hysteria",
        "xray": "runtime/Dockerfile.xray",
    }
    images: list[dict[str, str]] = []
    for index, (name, dockerfile) in enumerate(dockerfiles.items(), start=1):
        digest_hex = str(index) * 64
        digest = f"sha256:{digest_hex}"
        reference = f"ghcr.io/a1exzabr/ezopenpn-{name}"
        sbom = {"name": name, "spdxVersion": "SPDX-2.3"}
        sbom_bytes = (json.dumps(sbom, sort_keys=True) + "\n").encode()
        (sbom_dir / f"{name}.spdx.json").write_bytes(sbom_bytes)
        provenance = {
            "buildDefinition": {
                "buildType": "https://github.com/A1exZabr/EzOpenPN/images@v1",
                "externalParameters": {
                    "dockerfile": dockerfile,
                    "imageName": name,
                    "sourceCommit": commit,
                },
                "internalParameters": {"runnerEnvironment": "github-hosted"},
                "resolvedDependencies": [
                    {
                        "digest": {"gitCommit": commit},
                        "uri": f"git+https://github.com/A1exZabr/EzOpenPN@{commit}",
                    }
                ],
            },
            "runDetails": {
                "builder": {"id": identity},
                "metadata": {
                    "invocationId": (
                        "https://github.com/A1exZabr/EzOpenPN/actions/runs/1/attempts/1"
                    )
                },
            },
        }
        (provenance_dir / f"{name}.slsa.json").write_text(
            json.dumps(provenance, sort_keys=True) + "\n", encoding="utf-8"
        )

        def signed(
            predicate_type: str,
            predicate: dict[str, object],
            subject_reference: str,
            subject_digest: str,
        ) -> str:
            statement = {
                "_type": "https://in-toto.io/Statement/v1",
                "predicateType": predicate_type,
                "subject": [
                    {"name": subject_reference, "digest": {"sha256": subject_digest}}
                ],
                "predicate": predicate,
            }
            payload = base64.b64encode(json.dumps(statement).encode()).decode()
            return json.dumps([{"payload": payload}]) + "\n"

        (cosign_data / f"{name}.slsaprovenance1.json").write_text(
            signed(
                "https://slsa.dev/provenance/v1", provenance, reference, digest_hex
            ),
            encoding="utf-8",
        )
        (cosign_data / f"{name}.spdxjson.json").write_text(
            signed("https://spdx.dev/Document", sbom, reference, digest_hex),
            encoding="utf-8",
        )
        images.append(
            {
                "name": name,
                "reference": reference,
                "digest": digest,
                "sbom_path": f"{name}.spdx.json",
                "sbom_sha256": hashlib.sha256(sbom_bytes).hexdigest(),
                "provenance_subject": f"{reference}@{digest}",
                "workflow_identity": identity,
            }
        )

    manifest = tmp_path / "images.release.json"
    manifest.write_text(
        json.dumps(
            {
                "schema": 1,
                "source": {"repository": "A1exZabr/EzOpenPN", "commit": commit},
                "images": images,
            }
        ),
        encoding="utf-8",
    )
    environment = os.environ | {
        "FAKE_COSIGN_DATA": str(cosign_data),
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
    }
    command = [
        "bash",
        str(ROOT / "tools/verify_image_attestations.sh"),
        "--manifest",
        str(manifest),
        "--sbom-dir",
        str(sbom_dir),
        "--provenance-dir",
        str(provenance_dir),
    ]
    accepted = subprocess.run(command, env=environment, capture_output=True, text=True)
    assert accepted.returncode == 0, accepted.stderr
    assert "verified 5 signed image(s)" in accepted.stdout

    changed = json.loads((provenance_dir / "control.slsa.json").read_text())
    changed["buildDefinition"]["externalParameters"]["sourceCommit"] = "f" * 40
    (provenance_dir / "control.slsa.json").write_text(json.dumps(changed), encoding="utf-8")
    rejected = subprocess.run(command, env=environment, capture_output=True, text=True)
    assert rejected.returncode == 1
    assert "invalid provenance predicate for control" in rejected.stderr
