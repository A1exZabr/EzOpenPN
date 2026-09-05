from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools/publication_audit.sh"


def test_publication_audit_covers_every_release_boundary() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    for required in (
        "content_guard.py",
        "history_guard.py",
        "validate_evidence.py",
        "gitleaks git",
        "reuse lint",
        "git verify-tag",
        "verify_release.sh --published",
        "sha_pinning_required",
        "required_status_checks",
        "CI",
        "CodeQL",
        "Images",
        "VM Matrix",
        "Evidence",
    ):
        assert required in source


def test_publication_audit_never_changes_visibility_or_publishes() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert "gh repo edit" not in source
    assert "--draft=false" not in source
    assert "--visibility" not in source
    assert "git push" not in source


def test_local_audit_reports_current_missing_evidence_without_crashing() -> None:
    result = subprocess.run(
        ["bash", str(SCRIPT), "--local-only"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert "external_evidence_missing" in payload["blockers"]
    assert result.stderr == ""


@pytest.mark.parametrize(
    ("phase", "visibility", "accepted"),
    [
        ("private", "private", True),
        ("private", "public", False),
        ("public", "public", True),
        ("public", "private", False),
        ("public", "internal", False),
    ],
)
def test_metadata_audit_enforces_visibility_for_selected_phase(
    tmp_path: Path, phase: str, visibility: str, accepted: bool
) -> None:
    # Execute the actual embedded metadata checker with local API response data.
    source = SCRIPT.read_text(encoding="utf-8")
    match = re.search(r"<<'PY' >\"\$audit_root/metadata-results\"\n(.*?)\nPY\n", source, re.S)
    assert match is not None
    metadata = tmp_path / "repository.json"
    metadata.write_text(
        json.dumps(
            {
                "visibility": visibility,
                "fork": False,
                "default_branch": "main",
                "archived": False,
                "disabled": False,
                "description": "Самостоятельный сервер защищённых подключений",
            }
        ),
        encoding="utf-8",
    )
    result = subprocess.run(
        [sys.executable, "-", phase, str(metadata)],
        input=match.group(1),
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stderr == ""
    assert result.stdout == ("" if accepted else "blocker:repository_visibility_invalid\n")
