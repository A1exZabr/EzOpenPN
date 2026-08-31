from __future__ import annotations

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REQUIRED_TOOLS = {
    "actionlint",
    "bats",
    "cosign",
    "gitleaks",
    "govulncheck",
    "lychee",
    "reuse",
    "shellcheck",
    "syft",
    "trivy",
}


def test_security_runner_invokes_every_required_gate() -> None:
    script = (ROOT / "tools/run_security_checks.sh").read_text(encoding="utf-8")
    for command in ("bandit", "pip-audit", "gitleaks", "trivy", "govulncheck"):
        assert command in script


def test_toolchain_config_and_lock_cover_required_tools() -> None:
    config = tomllib.loads((ROOT / "tools/toolchain.toml").read_text(encoding="utf-8"))
    lock = tomllib.loads((ROOT / "tools/toolchain.lock").read_text(encoding="utf-8"))
    assert set(config["tools"]) == REQUIRED_TOOLS
    assert set(lock["tools"]) == REQUIRED_TOOLS
    for name in REQUIRED_TOOLS:
        assert lock["tools"][name]["version"] == config["tools"][name]["version"]
        assert re.fullmatch(r"[0-9a-f]{64}", lock["tools"][name]["sha256"])
        assert lock["tools"][name]["url"].startswith("https://")


def test_locked_installer_filters_artifacts_before_download() -> None:
    script = (ROOT / "tools/lock_toolchain.sh").read_text(encoding="utf-8")
    assert 'selected = set(sys.argv[2:])' in script
    assert "if selected and name not in selected:" in script
    assert "requested_tools" not in script


def test_workflows_pin_actions_to_full_commit_sha() -> None:
    action = re.compile(r"^\s*-?\s*uses:\s*[^\s@]+@([^\s#]+)", re.MULTILINE)
    for path in sorted((ROOT / ".github/workflows").glob("*.yml")):
        references = action.findall(path.read_text(encoding="utf-8"))
        assert references, path
        assert all(re.fullmatch(r"[0-9a-f]{40}", reference) for reference in references)
