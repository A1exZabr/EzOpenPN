from __future__ import annotations

import json
import subprocess
from pathlib import Path

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


def test_publication_report_keeps_repository_private_while_evidence_is_missing() -> None:
    report = (ROOT / "docs/releases/publication-report.md").read_text(encoding="utf-8")
    assert "Итог: НЕ ГОТОВ К ПУБЛИКАЦИИ" in report
    assert "Репозиторий остаётся приватным" in report
    assert "external_evidence_missing" in report
    assert "branch_protection_deferred_by_private_plan" in report
