#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

[[ $# -eq 5 || $# -eq 6 ]] || exit 2
workflow="$1"
run_id="$2"
commit="$3"
artifact_name="$4"
prefix="$5"
[[ "$run_id" =~ ^[1-9][0-9]*$ && "$commit" =~ ^[0-9a-f]{40}$ \
  && "$prefix" =~ ^[a-z_]+$ ]] || exit 2
repository_root="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/ezopenpn-release-input.XXXXXXXX")"
trap 'case "$scratch" in "${TMPDIR:-/tmp}"/ezopenpn-release-input.*) rm -rf -- "$scratch" ;; esac' EXIT

gh api "repos/A1exZabr/EzOpenPN/actions/runs/$run_id" >"$scratch/run.json"
run_options=(--workflow "$workflow" --commit "$commit" --run-id "$run_id")
if [[ $# -eq 6 ]]; then
  run_options+=(--tag "$6")
fi
attempt="$(python3 "$repository_root/tools/check_workflow_run.py" "$scratch/run.json" \
  "${run_options[@]}")"
gh api --paginate --slurp \
  "repos/A1exZabr/EzOpenPN/actions/runs/$run_id/artifacts" >"$scratch/artifacts.json"
artifact_id="$(jq -er --arg name "$artifact_name" --arg commit "$commit" \
  --argjson run "$run_id" '
  [.[].artifacts[] | select(.name == $name)] |
  if length == 1 and .[0].expired == false
    and .[0].workflow_run.id == $run and .[0].workflow_run.head_sha == $commit
    and (.[0].id | type) == "number" and .[0].id > 0
  then .[0].id else error("release artifact missing, expired, ambiguous or unrelated") end
  ' "$scratch/artifacts.json")"
printf '%s_artifact_id=%s\n%s_run_attempt=%s\n' "$prefix" "$artifact_id" "$prefix" "$attempt"
