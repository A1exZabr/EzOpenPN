from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize(
    "payload",
    [
        {"tag_name": "v0.1.10", "draft": False, "prerelease": True},
        {"tag_name": "v0.1.10", "draft": True, "prerelease": False},
        {"tag_name": "v0.1.10; echo unsafe", "draft": False, "prerelease": False},
        {"tag_name": "v0.1.10"},
        {"message": "Not Found"},
    ],
)
def test_stable_discovery_rejects_unpublished_or_malformed_release(tmp_path: Path, payload):
    (tmp_path / "response").write_text(json.dumps(payload))
    curl = tmp_path / "curl"
    curl.write_text('#!/bin/sh\ncat "$GITHUB_RELEASE_FIXTURE"\n')
    curl.chmod(0o755)
    result = subprocess.run(
        ["bash", "-c", "source installer/install.sh; _resolve_release_version"],
        cwd=ROOT,
        env=os.environ
        | {
            "PATH": f"{tmp_path}:{os.environ['PATH']}",
            "GITHUB_RELEASE_FIXTURE": str(tmp_path / "response"),
            "EZOPENPN_EXPECTED_VERSION": "",
            "EZOPENPN_RELEASE_BASE_URL": "",
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 31
    assert result.stdout == ""
    assert "E_RELEASE_VERIFY" in result.stderr


@pytest.mark.parametrize("private", [False, True])
def test_public_image_check_pulls_all_pinned_images_without_saved_login(tmp_path: Path, private):
    manifest = ROOT / "tests/release/fixtures/images.release.json"
    subjects = [
        f"{item['reference']}@{item['digest']}"
        for item in json.loads(manifest.read_text())["images"]
    ]
    docker = tmp_path / "docker"
    docker.write_text(
        "#!/usr/bin/env python3\nimport json,os,sys\nfrom pathlib import Path\n"
        "args=sys.argv[1:]\n"
        "assert args[:1]==['--config'] and args[2:5]==['pull','--platform','linux/amd64']\n"
        "assert not (Path(args[1])/'config.json').exists()\n"
        "with open(os.environ['PULL_RECORD'],'a') as f: f.write(args[5]+'\\n')\n"
        "raise SystemExit(1 if os.environ['PRIVATE_IMAGE']=='1' else 0)\n"
    )
    docker.chmod(0o755)
    result = subprocess.run(
        ["bash", str(ROOT / "tools/verify_public_images.sh"), str(manifest)],
        env=os.environ
        | {
            "PATH": f"{tmp_path}:{os.environ['PATH']}",
            "DOCKER_CONFIG": "/must-not-use-saved-login",
            "PRIVATE_IMAGE": "1" if private else "0",
            "PULL_RECORD": str(tmp_path / "pulls"),
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == (1 if private else 0), result.stderr
    assert (tmp_path / "pulls").read_text().splitlines() == (subjects[:1] if private else subjects)
