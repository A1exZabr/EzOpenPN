#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

repository_root="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repository_root"

_require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'required security tool is unavailable: %s\n' "$1" >&2
    return 127
  }
}

for command_name in gitleaks go govulncheck trivy uv; do
  _require_command "$command_name"
done

audit_requirements=""
trivy_report=""
_cleanup() {
  if [[ -n "$audit_requirements" ]]; then
    case "$audit_requirements" in
      /tmp/ezopenpn-audit.* | "${TMPDIR:-/tmp}"/ezopenpn-audit.*)
        rm -f -- "$audit_requirements"
        ;;
    esac
  fi
  if [[ -n "$trivy_report" ]]; then
    case "$trivy_report" in
      /tmp/ezopenpn-trivy.* | "${TMPDIR:-/tmp}"/ezopenpn-trivy.*)
        rm -f -- "$trivy_report"
        ;;
    esac
  fi
}
trap _cleanup EXIT

uv run bandit -q -c pyproject.toml -r control/src installer tools
audit_requirements="$(mktemp "${TMPDIR:-/tmp}/ezopenpn-audit.XXXXXXXX")"
uv export --frozen --all-groups --no-emit-project \
  --format requirements.txt --output-file "$audit_requirements" --quiet
uv run pip-audit --strict --requirement "$audit_requirements"
rm -f -- "$audit_requirements"
audit_requirements=""
gitleaks git --redact --no-banner --config .gitleaks.toml
trivy_report="$(mktemp "${TMPDIR:-/tmp}/ezopenpn-trivy.XXXXXXXX")"
if ! trivy fs \
  --quiet \
  --scanners vuln,secret,misconfig \
  --severity HIGH,CRITICAL \
  --exit-code 1 \
  --ignore-unfixed \
  --skip-dirs .git \
  --skip-dirs .venv \
  --skip-dirs .worktrees \
  --format json \
  --output "$trivy_report" \
  .; then
  uv run python - "$trivy_report" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
findings: list[tuple[str, str, str, str]] = []
for result in report.get("Results") or []:
    target = result.get("Target", "unknown")
    for finding in result.get("Vulnerabilities") or []:
        findings.append(
            (
                target,
                "vulnerability",
                finding.get("VulnerabilityID", "unknown"),
                finding.get("Severity", "unknown"),
            )
        )
    for finding in result.get("Misconfigurations") or []:
        findings.append(
            (
                target,
                "misconfiguration",
                finding.get("ID", "unknown"),
                finding.get("Severity", "unknown"),
            )
        )
    for finding in result.get("Secrets") or []:
        findings.append(
            (
                target,
                "secret",
                finding.get("RuleID", "unknown"),
                finding.get("Severity", "unknown"),
            )
        )
print(f"Trivy rejected {len(findings)} finding(s).", file=sys.stderr)
for target, kind, identifier, severity in findings[:100]:
    print(f"{severity}\t{kind}\t{identifier}\t{target}", file=sys.stderr)
if len(findings) > 100:
    print(f"{len(findings) - 100} additional finding(s) omitted.", file=sys.stderr)
PY
  exit 1
fi
rm -f -- "$trivy_report"
trivy_report=""
(
  cd runtime
  GOTOOLCHAIN=local govulncheck ./...
)
