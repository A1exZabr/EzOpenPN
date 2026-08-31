from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]


def _run_gate(tmp_path: Path, results: list[dict[str, object]]) -> subprocess.CompletedProcess[str]:
    report_root = tmp_path / "reports"
    report_root.mkdir()
    (report_root / "result.sarif").write_text(
        json.dumps({"version": "2.1.0", "runs": [{"results": results}]}),
        encoding="utf-8",
    )
    return subprocess.run(
        [sys.executable, str(_ROOT / "tools/check_sarif.py"), str(report_root)],
        check=False,
        capture_output=True,
        text=True,
    )


def test_sarif_gate_reports_safe_source_coordinate(tmp_path: Path) -> None:
    result = _run_gate(
        tmp_path,
        [
            {
                "level": "warning",
                "ruleId": "py/example",
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "src/example.py"},
                            "region": {"startLine": 17},
                        }
                    }
                ],
            }
        ],
    )

    assert result.returncode == 1
    assert "warning\tpy/example\tsrc/example.py:17" in result.stderr


def test_sarif_gate_accepts_only_non_actionable_results(tmp_path: Path) -> None:
    result = _run_gate(
        tmp_path,
        [{"level": "note", "ruleId": "py/informational"}],
    )

    assert result.returncode == 0
    assert "CodeQL accepted 1 SARIF report(s)." in result.stdout
