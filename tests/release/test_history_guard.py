from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

RELEASE_TEST_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from history_guard import scan_git_history  # noqa: E402


def _git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _write(path: Path, value: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        data = value.encode("utf-8")
        while data:
            written = os.write(descriptor, data)
            if written <= 0:
                raise OSError("short fixture write")
            data = data[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _repository(tmp_path: Path) -> Path:
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "--initial-branch=main")
    _git(repository, "config", "user.name", "Fixture Author")
    _git(repository, "config", "user.email", "fixture@example.invalid")
    _write(repository / "README.md", "# Neutral fixture\n")
    _git(repository, "add", "README.md")
    _git(repository, "commit", "-m", "initial neutral commit")
    return repository


def _prohibited_label() -> str:
    return "".join(chr(codepoint) for codepoint in (118, 112, 110))


def test_guard_finds_prohibited_content_outside_current_tree(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    path = repository / "guide.txt"
    _write(path, f"historical {_prohibited_label()} label\n")
    _git(repository, "add", "guide.txt")
    _git(repository, "commit", "-m", "add historical fixture")
    _write(path, "neutral replacement\n")
    _git(repository, "add", "guide.txt")
    _git(repository, "commit", "-m", "replace historical fixture")

    result = scan_git_history(repository)

    assert result.ok is False
    assert any(finding.kind == "prohibited_content" for finding in result.findings)
    assert all(re.fullmatch(r"[0-9a-f]{40}", finding.object_id) for finding in result.findings)
    assert all(
        finding.path_sha256 is None or len(finding.path_sha256) == 64 for finding in result.findings
    )


def test_guard_scans_historical_paths_and_ref_names(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    label = _prohibited_label()
    path = repository / f"old-{label}-name.txt"
    _write(path, "neutral body\n")
    _git(repository, "add", path.name)
    _git(repository, "commit", "-m", "add neutral body")
    _git(repository, "branch", f"archive/{label}-name")

    result = scan_git_history(repository)

    kinds = {finding.kind for finding in result.findings}
    assert "prohibited_path" in kinds
    assert "prohibited_ref" in kinds
    assert all(finding.safe_location != path.name for finding in result.findings)


def test_guard_rejects_prohibited_typography_in_old_commit(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    _write(repository / "notes.txt", "left" + chr(0x2014) + "right\n")
    _git(repository, "add", "notes.txt")
    _git(repository, "commit", "-m", "add typography fixture")

    result = scan_git_history(repository)

    assert any(finding.kind == "prohibited_typography" for finding in result.findings)


def test_guard_accepts_single_root_neutral_history(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    _write(repository / "guide.txt", "safe content\n")
    _git(repository, "add", "guide.txt")
    _git(repository, "commit", "-m", "add guide")

    result = scan_git_history(repository)

    assert result.ok is True
    assert result.findings == ()
    assert result.root_commits == 1
    assert result.commits_scanned == 2
    assert result.blobs_scanned == 2


def test_guard_rejects_multiple_root_histories(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    _git(repository, "checkout", "--orphan", "other-root")
    _git(repository, "rm", "-rf", ".")
    _write(repository / "OTHER.md", "neutral second root\n")
    _git(repository, "add", "OTHER.md")
    _git(repository, "commit", "-m", "second root")

    result = scan_git_history(repository)

    assert result.ok is False
    assert any(finding.kind == "multiple_roots" for finding in result.findings)
