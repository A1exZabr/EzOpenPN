from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tarfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[2]
SOURCE_COMMIT = "0123456789abcdef0123456789abcdef01234567"
SOURCE_DATE_EPOCH = "1800000000"


def build_release(output: Path) -> Path:
    environment = os.environ.copy()
    environment["SOURCE_DATE_EPOCH"] = SOURCE_DATE_EPOCH
    subprocess.run(
        [
            "bash",
            "tools/build_release.sh",
            "--version",
            "v0.1.0",
            "--source-commit",
            SOURCE_COMMIT,
            "--images-manifest",
            "tests/release/fixtures/images.release.json",
            "--output",
            str(output),
        ],
        cwd=ROOT,
        env=environment,
        check=True,
    )
    return output


def test_bundle_contains_only_allowlisted_roots(tmp_path: Path) -> None:
    output = build_release(tmp_path / "release")
    archive = output / "ezopenpn-bundle.tar.gz"
    with tarfile.open(archive, "r:gz") as bundle:
        members = bundle.getmembers()
    roots = {PurePosixPath(member.name).parts[0] for member in members}
    assert roots <= {
        "deploy",
        "installer",
        "manifest.json",
        "LICENSE",
        "THIRD_PARTY_NOTICES.md",
    }
    assert "manifest.json" in roots
    assert len({member.name for member in members}) == len(members)
    assert all(member.uid == 0 and member.gid == 0 for member in members)
    assert all(member.mtime == int(SOURCE_DATE_EPOCH) for member in members)
    assert all(member.isdir() or member.isfile() for member in members)


def test_manifest_covers_payload_and_all_runtime_images(tmp_path: Path) -> None:
    output = build_release(tmp_path / "release")
    archive = output / "ezopenpn-bundle.tar.gz"
    with tarfile.open(archive, "r:gz") as bundle:
        manifest_stream = bundle.extractfile("manifest.json")
        assert manifest_stream is not None
        manifest = json.load(manifest_stream)
        assert manifest["version"] == "v0.1.0"
        assert manifest["source_commit"] == SOURCE_COMMIT
        assert manifest["database_schema"] == {
            "minimum": "0001_initial",
            "maximum": "0001_initial",
        }
        assert set(manifest["images"]) == {
            "control",
            "xray",
            "hysteria",
            "gateway",
            "cert-sync",
        }
        for name, expected in manifest["files"].items():
            stream = bundle.extractfile(name)
            assert stream is not None
            assert hashlib.sha256(stream.read()).hexdigest() == expected


def test_release_assets_verify_and_bootstrap_is_exact(tmp_path: Path) -> None:
    output = build_release(tmp_path / "release")
    assert (output / "install.sh").read_bytes() == (ROOT / "installer/install.sh").read_bytes()
    assert (output / "install.sh").stat().st_mode & 0o111
    subprocess.run(
        ["bash", "tools/verify_release.sh", str(output)], cwd=ROOT, check=True
    )

    with (output / "ezopenpn-bundle.tar.gz").open("ab") as stream:
        stream.write(b"tamper")
    rejected = subprocess.run(
        ["bash", "tools/verify_release.sh", str(output)],
        cwd=ROOT,
        check=False,
    )
    assert rejected.returncode != 0


def test_release_workflow_is_manual_and_evidence_gated() -> None:
    workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    assert "workflow_dispatch:" in workflow
    assert "\n  push:" not in workflow
    assert "evidence_run_id:" in workflow
    assert "images_run_id:" in workflow
    assert "git verify-tag" in workflow
    assert "validate_evidence.py" in workflow
    assert "--draft" in workflow
    assert "--draft=false" in workflow
    assert workflow.index("verify_release.sh --signed") < workflow.index("--draft=false")
