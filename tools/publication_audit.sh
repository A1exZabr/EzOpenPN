#!/usr/bin/env bash

set -uo pipefail
umask 077

repository_root="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
phase="private"
local_only=false
release_tag="v0.1.0"

usage() {
  printf '%s\n' \
    'usage: tools/publication_audit.sh [--phase private|public] [--tag vMAJOR.MINOR.PATCH] [--local-only]' >&2
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --phase)
      [[ $# -ge 2 ]] || usage
      phase="$2"
      shift 2
      ;;
    --tag)
      [[ $# -ge 2 ]] || usage
      release_tag="$2"
      shift 2
      ;;
    --local-only)
      local_only=true
      shift
      ;;
    *)
      usage
      ;;
  esac
done

[[ "$phase" == private || "$phase" == public ]] || usage
[[ "$release_tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || usage

audit_root="$(mktemp -d "${TMPDIR:-/tmp}/ezopenpn-publication.XXXXXXXX")"
blockers_file="$audit_root/blockers"
warnings_file="$audit_root/warnings"
: >"$blockers_file"
: >"$warnings_file"

cleanup() {
  case "$audit_root" in
    /tmp/ezopenpn-publication.* | "${TMPDIR:-/tmp}"/ezopenpn-publication.*)
      rm -rf -- "$audit_root"
      ;;
  esac
}
trap cleanup EXIT

add_blocker() {
  printf '%s\n' "$1" >>"$blockers_file"
}

add_warning() {
  printf '%s\n' "$1" >>"$warnings_file"
}

cd "$repository_root" || {
  add_blocker repository_unavailable
}

if [[ -n "$(git status --porcelain=v1 --untracked-files=all 2>/dev/null)" ]]; then
  add_blocker worktree_not_clean
fi

if ! git fsck --full --strict --no-dangling >/dev/null 2>&1; then
  add_blocker git_integrity_failed
fi

if command -v uv >/dev/null 2>&1; then
  if ! uv run python tools/content_guard.py . >/dev/null 2>&1; then
    add_blocker current_tree_content_failed
  fi
  if ! uv run python tools/history_guard.py . >/dev/null 2>&1; then
    add_blocker history_guard_failed
  fi
  if ! uv run python tests/release/validate_evidence.py docs/releases/evidence \
    >/dev/null 2>&1; then
    add_blocker external_evidence_missing
  fi
else
  add_blocker uv_unavailable
fi

if command -v gitleaks >/dev/null 2>&1; then
  if ! gitleaks git --redact --no-banner --config .gitleaks.toml >/dev/null 2>&1; then
    add_blocker history_secret_scan_failed
  fi
else
  add_blocker gitleaks_unavailable
fi

if command -v reuse >/dev/null 2>&1; then
  if ! reuse lint >/dev/null 2>&1; then
    add_blocker license_audit_failed
  fi
elif command -v uvx >/dev/null 2>&1; then
  if ! uvx --from reuse==5.1.1 reuse lint >/dev/null 2>&1; then
    add_blocker license_audit_failed
  fi
else
  add_blocker reuse_unavailable
fi

remote_names="$(git remote 2>/dev/null || true)"
if [[ "$remote_names" != $'forgejo\ngithub' ]]; then
  add_blocker remote_set_invalid
fi
forgejo_expected="https://git.alexzabrodin.pro/alex/EzOpenPN.git"
github_expected="git@github.com:A1exZabr/EzOpenPN.git"
fetch_url="$(git remote get-url forgejo 2>/dev/null || true)"
push_url="$(git remote get-url --push forgejo 2>/dev/null || true)"
if [[ "$fetch_url" != "$forgejo_expected" || "$push_url" != "$forgejo_expected" ]]; then
  add_blocker remote_fetch_invalid
fi
fetch_url="$(git remote get-url github 2>/dev/null || true)"
push_url="$(git remote get-url --push github 2>/dev/null || true)"
if [[ "$fetch_url" != "$github_expected" || "$push_url" != "$github_expected" ]]; then
  add_blocker remote_push_invalid
fi
{
  git remote -v 2>/dev/null || true
} >"$audit_root/remotes.txt"
if command -v uv >/dev/null 2>&1 \
  && ! uv run python tools/content_guard.py "$audit_root" >/dev/null 2>&1; then
  add_blocker remote_content_failed
fi

if [[ "$local_only" == true ]]; then
  python3 - "$phase" "$blockers_file" "$warnings_file" <<'PY'
import json
import sys
from pathlib import Path

phase, blockers_path, warnings_path = sys.argv[1:]
blockers = sorted(set(Path(blockers_path).read_text(encoding="utf-8").splitlines()))
warnings = sorted(set(Path(warnings_path).read_text(encoding="utf-8").splitlines()))
print(json.dumps({"blockers": blockers, "ok": not blockers, "phase": phase, "warnings": warnings}, sort_keys=True))
raise SystemExit(0 if not blockers else 1)
PY
  exit $?
fi

if ! command -v gh >/dev/null 2>&1; then
  add_blocker github_cli_unavailable
else
  if gh api repos/A1exZabr/EzOpenPN >"$audit_root/repository.json" 2>/dev/null; then
    python3 - "$phase" "$audit_root/repository.json" <<'PY' >"$audit_root/metadata-results"
import json
import sys

_phase, path = sys.argv[1:]
data = json.load(open(path, encoding="utf-8"))
checks = (
    (data.get("visibility") == "private", "repository_visibility_invalid"),
    (data.get("fork") is False, "repository_is_fork"),
    (data.get("default_branch") == "main", "default_branch_invalid"),
    (data.get("archived") is False, "repository_archived"),
    (data.get("disabled") is False, "repository_disabled"),
    (
        data.get("description") == "Самостоятельный сервер защищённых подключений",
        "repository_description_invalid",
    ),
)
for passed, code in checks:
    if not passed:
        print("blocker:" + code)
PY
    while IFS= read -r decision; do
      [[ -n "$decision" ]] || continue
      add_blocker "${decision#blocker:}"
    done <"$audit_root/metadata-results"
  else
    add_blocker github_metadata_unavailable
  fi

  if gh api repos/A1exZabr/EzOpenPN/actions/permissions \
    >"$audit_root/actions.json" 2>/dev/null \
    && gh api repos/A1exZabr/EzOpenPN/actions/permissions/workflow \
      >"$audit_root/workflow-permissions.json" 2>/dev/null; then
    python3 - "$audit_root/actions.json" "$audit_root/workflow-permissions.json" <<'PY' \
      >"$audit_root/action-results"
import json
import sys

actions = json.load(open(sys.argv[1], encoding="utf-8"))
workflow = json.load(open(sys.argv[2], encoding="utf-8"))
if actions.get("enabled") is not True:
    print("actions_disabled")
if actions.get("sha_pinning_required") is not True:
    print("action_sha_pinning_disabled")
if workflow.get("default_workflow_permissions") != "read":
    print("workflow_permissions_not_read_only")
if workflow.get("can_approve_pull_request_reviews") is not False:
    print("workflow_review_approval_enabled")
PY
    while IFS= read -r code; do
      [[ -n "$code" ]] && add_blocker "$code"
    done <"$audit_root/action-results"
  else
    add_blocker actions_permissions_unavailable
  fi

  if gh api repos/A1exZabr/EzOpenPN/branches/main/protection \
    >"$audit_root/protection.json" 2>/dev/null; then
    python3 - "$audit_root/protection.json" <<'PY' >"$audit_root/protection-results"
import json
import sys

protection = json.load(open(sys.argv[1], encoding="utf-8"))
required_status_checks = protection.get("required_status_checks") or {}
if required_status_checks.get("strict") is not True:
    print("required_checks_not_strict")
contexts = required_status_checks.get("contexts") or []
checks = required_status_checks.get("checks") or []
if not contexts and not checks:
    print("required_checks_missing")
signatures = protection.get("required_signatures") or {}
if signatures.get("enabled") is not True:
    print("signed_commits_not_required")
PY
    while IFS= read -r code; do
      [[ -n "$code" ]] && add_blocker "$code"
    done <"$audit_root/protection-results"
  elif [[ "$phase" == public ]]; then
    add_blocker branch_protection_unavailable
  else
    add_warning branch_protection_deferred_by_private_plan
  fi

  head_commit="$(git rev-parse HEAD 2>/dev/null || true)"
  current_branch="$(git branch --show-current 2>/dev/null || true)"
  remote_commit="$(gh api repos/A1exZabr/EzOpenPN/git/ref/heads/main --jq .object.sha 2>/dev/null || true)"
  [[ "$current_branch" == main ]] || add_blocker local_branch_not_main
  [[ -n "$head_commit" && "$head_commit" == "$remote_commit" ]] \
    || add_blocker local_remote_main_mismatch

  if gh run list --repo A1exZabr/EzOpenPN --commit "$head_commit" --limit 100 \
    --json workflowName,status,conclusion,headSha >"$audit_root/runs.json" 2>/dev/null; then
    python3 - "$head_commit" "$audit_root/runs.json" <<'PY' >"$audit_root/run-results"
import json
import sys

commit, path = sys.argv[1:]
runs = json.load(open(path, encoding="utf-8"))
successful = {
    run.get("workflowName")
    for run in runs
    if run.get("headSha") == commit
    and run.get("status") == "completed"
    and run.get("conclusion") == "success"
}
for workflow in sorted({"CI", "CodeQL", "Images", "VM Matrix", "Evidence"} - successful):
    print("workflow_missing:" + workflow.replace(" ", "_").casefold())
PY
    while IFS= read -r code; do
      [[ -n "$code" ]] && add_blocker "$code"
    done <"$audit_root/run-results"
  else
    add_blocker workflow_status_unavailable
  fi

  if git show-ref --verify --quiet "refs/tags/$release_tag" \
    && [[ "$(git cat-file -t "refs/tags/$release_tag" 2>/dev/null || true)" == tag ]] \
    && [[ "$(git rev-parse "$release_tag^{commit}" 2>/dev/null || true)" == "$head_commit" ]] \
    && git verify-tag "$release_tag" >/dev/null 2>&1; then
    :
  else
    add_blocker signed_release_tag_missing
  fi

  if gh release view "$release_tag" --repo A1exZabr/EzOpenPN \
    --json isDraft,isPrerelease,tagName >"$audit_root/release.json" 2>/dev/null; then
    python3 - "$audit_root/release.json" <<'PY' >"$audit_root/release-results"
import json
import sys

release = json.load(open(sys.argv[1], encoding="utf-8"))
if release.get("isDraft") is not False:
    print("private_release_still_draft")
if release.get("isPrerelease") is not False:
    print("release_is_prerelease")
PY
    while IFS= read -r code; do
      [[ -n "$code" ]] && add_blocker "$code"
    done <"$audit_root/release-results"
    if command -v cosign >/dev/null 2>&1; then
      install -d -m 0700 "$audit_root/release-assets"
      if gh release download "$release_tag" --repo A1exZabr/EzOpenPN \
        --dir "$audit_root/release-assets" >/dev/null 2>&1; then
        if ! bash tools/verify_release.sh --signed "$audit_root/release-assets" \
          >/dev/null 2>&1; then
          add_blocker release_asset_verification_failed
        fi
      else
        add_blocker release_asset_download_failed
      fi
    else
      add_blocker cosign_unavailable
    fi
  else
    add_blocker private_release_missing
  fi
fi

python3 - "$phase" "$blockers_file" "$warnings_file" <<'PY'
import json
import sys
from pathlib import Path

phase, blockers_path, warnings_path = sys.argv[1:]
blockers = sorted(set(Path(blockers_path).read_text(encoding="utf-8").splitlines()))
warnings = sorted(set(Path(warnings_path).read_text(encoding="utf-8").splitlines()))
print(json.dumps({"blockers": blockers, "ok": not blockers, "phase": phase, "warnings": warnings}, sort_keys=True))
raise SystemExit(0 if not blockers else 1)
PY
