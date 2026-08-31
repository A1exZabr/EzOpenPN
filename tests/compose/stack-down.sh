#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
state_path="/tmp/ezopenpn-stack-state-$(id -u).json"
if [[ ! -f "$state_path" ]]; then
  exit 0
fi

state_values=()
while IFS= read -r value; do
  state_values+=("$value")
done < <(python3 - "$state_path" <<'PY'
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

state_path = Path(sys.argv[1])
state = json.loads(state_path.read_text(encoding="utf-8"))
root = Path(state["root"]).resolve()
temporary_root = Path(tempfile.gettempdir()).resolve()
if root.parent != temporary_root or not root.name.startswith("ezopenpn-stack."):
    raise SystemExit("unsafe stack root")
print(root)
print(state["project"])
print(state["environment_file"])
PY
)
if [[ ${#state_values[@]} -ne 3 ]]; then
  echo "invalid stack state" >&2
  exit 65
fi
test_root="${state_values[0]}"
project="${state_values[1]}"
environment_path="${state_values[2]}"

rotation_ids=()
while IFS= read -r container_id; do
  if [[ -n "$container_id" ]]; then
    rotation_ids+=("$container_id")
  fi
done < <(docker ps -aq --filter "label=com.ezopenpn.stack-test=${project}")
if [[ ${#rotation_ids[@]} -gt 0 ]]; then
  docker rm --force "${rotation_ids[@]}" >/dev/null 2>&1 || true
fi

docker compose \
  --env-file "$environment_path" \
  -f "${repository_root}/deploy/compose.yaml" \
  -f "${repository_root}/tests/compose/stack-override.yaml" \
  --project-name "$project" \
  down --volumes --remove-orphans >/dev/null 2>&1 || true
sudo rm -rf -- "$test_root"
rm -f -- "$state_path"
