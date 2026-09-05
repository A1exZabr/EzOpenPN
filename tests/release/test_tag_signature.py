from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("workflow_name", ["release.yml", "candidate-release.yml"])
@pytest.mark.parametrize("signature", ["trusted", "untrusted", "unsigned"])
def test_release_tag_gate_uses_explicit_trust_in_a_clean_runner(
    tmp_path: Path, workflow_name: str, signature: str
) -> None:
    environment = {
        "PATH": os.environ["PATH"],
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "RELEASE_TAG": "v0.1.0",
        "GITHUB_REF": "refs/tags/v0.1.0",
    }

    def run(*arguments: str) -> str:
        return subprocess.run(
            arguments, cwd=tmp_path, env=environment, check=True,
            capture_output=True, text=True,
        ).stdout.strip()

    run("git", "init", "-q")
    run("git", "config", "user.name", "Release test")
    run("git", "config", "user.email", "test@example.invalid")
    run("git", "commit", "--allow-empty", "-qm", "fixture")
    environment["GITHUB_SHA"] = run("git", "rev-parse", "HEAD")
    trusted_key = tmp_path / "trusted"
    run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(trusted_key))
    trust = tmp_path / ".github/release-allowed-signers"
    trust.parent.mkdir()
    trust.write_text(
        "ezopenpn-maintainer " + trusted_key.with_suffix(".pub").read_text(),
        encoding="utf-8",
    )
    if signature == "unsigned":
        run("git", "tag", "-a", "v0.1.0", "-m", "fixture")
    else:
        signing_key = trusted_key
        if signature == "untrusted":
            signing_key = tmp_path / "untrusted"
            run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(signing_key))
        run(
            "git", "-c", "gpg.format=ssh", "-c", f"user.signingkey={signing_key}",
            "tag", "-s", "v0.1.0", "-m", "fixture",
        )

    workflow = yaml.safe_load((ROOT / ".github/workflows" / workflow_name).read_text())
    gate = next(
        step["run"] for step in workflow["jobs"]["build"]["steps"]
        if "RELEASE_TAG" in step.get("env", {})
    )
    result = subprocess.run(
        ["bash", "-euo", "pipefail", "-c", gate],
        cwd=tmp_path, env=environment, capture_output=True, text=True,
    )

    assert (result.returncode == 0) is (signature == "trusted"), result.stderr
