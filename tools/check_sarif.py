from __future__ import annotations

import argparse
import json
import stat
import sys
from pathlib import Path

MAX_REPORT_BYTES = 64 * 1024 * 1024


def _results(path: Path) -> list[tuple[str, str]]:
    status = path.lstat()
    if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
        raise ValueError("SARIF input must be a regular file")
    if status.st_size > MAX_REPORT_BYTES:
        raise ValueError("SARIF input is too large")
    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("version") != "2.1.0" or not isinstance(document.get("runs"), list):
        raise ValueError("SARIF document is invalid")
    findings: list[tuple[str, str]] = []
    for run in document["runs"]:
        if not isinstance(run, dict):
            raise ValueError("SARIF run is invalid")
        results = run.get("results", [])
        if not isinstance(results, list):
            raise ValueError("SARIF results are invalid")
        for result in results:
            if not isinstance(result, dict):
                raise ValueError("SARIF result is invalid")
            level = result.get("level", "warning")
            if level not in {"error", "warning"}:
                continue
            rule_id = result.get("ruleId", "unknown-rule")
            if not isinstance(rule_id, str) or not rule_id or any(
                character in rule_id for character in "\r\n\t"
            ):
                rule_id = "unknown-rule"
            findings.append((level, rule_id))
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="Fail on actionable SARIF findings")
    parser.add_argument("directory", type=Path)
    arguments = parser.parse_args()
    root = arguments.directory.resolve(strict=True)
    if not root.is_dir():
        parser.error("SARIF path must be a directory")
    reports = sorted(root.rglob("*.sarif"))
    if not reports:
        print("no SARIF reports found", file=sys.stderr)
        return 2
    try:
        findings = sorted({finding for report in reports for finding in _results(report)})
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 2
    if findings:
        print(f"CodeQL rejected {len(findings)} rule(s).", file=sys.stderr)
        for level, rule_id in findings:
            print(f"{level}\t{rule_id}", file=sys.stderr)
        return 1
    print(f"CodeQL accepted {len(reports)} SARIF report(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
