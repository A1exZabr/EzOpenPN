from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
COMMIT = "a" * 40


def run_metadata() -> dict:
    return {
        "id": 12,
        "path": ".github/workflows/images.yml",
        "event": "workflow_dispatch",
        "head_sha": COMMIT,
        "head_branch": "main",
        "run_attempt": 2,
        "status": "completed",
        "conclusion": "success",
        "repository": {"full_name": "A1exZabr/EzOpenPN"},
        "head_repository": {"full_name": "A1exZabr/EzOpenPN"},
    }


def check(tmp_path: Path, payload: dict, *extra: str) -> subprocess.CompletedProcess[str]:
    path = tmp_path / "run.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools/check_workflow_run.py"),
            str(path),
            "--workflow",
            "images",
            "--commit",
            COMMIT,
            "--run-id",
            "12",
            *extra,
        ],
        text=True,
        capture_output=True,
        check=False,
    )


def test_accepts_successful_manual_run_and_returns_its_attempt(tmp_path: Path) -> None:
    result = check(tmp_path, run_metadata())
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "2"


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("id", 13),
        ("head_sha", "b" * 40),
        ("status", "in_progress"),
        ("conclusion", "failure"),
        ("event", "pull_request"),
        ("path", ".github/workflows/other.yml"),
        ("run_attempt", 0),
        ("repository", {"full_name": "other/repository"}),
        ("head_repository", {"full_name": "other/repository"}),
    ],
)
def test_rejects_untrusted_or_unrelated_run(tmp_path: Path, key: str, value: object) -> None:
    assert check(tmp_path, run_metadata()).returncode == 0
    payload = run_metadata() | {key: value}
    result = check(tmp_path, payload)
    assert result.returncode == 1
    assert "workflow run does not match" in result.stderr


def test_tag_bound_run_cannot_be_a_branch_dispatch(tmp_path: Path) -> None:
    assert check(tmp_path, run_metadata()).returncode == 0
    assert check(tmp_path, run_metadata(), "--tag", "v0.1.10").returncode == 1
    tagged = run_metadata() | {"head_branch": "v0.1.10"}
    assert check(tmp_path, tagged, "--tag", "v0.1.10").returncode == 0
