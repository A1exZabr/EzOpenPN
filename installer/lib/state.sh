#!/usr/bin/env bash

operation_checkpoint_path() {
  printf '%s/operations/current.json\n' "${EZOPENPN_STATE_ROOT:-/var/lib/ezopenpn}"
}

write_operation_checkpoint() {
  local operation="${1:-}"
  local phase="${2:-}"
  if [[ -z "$operation" || "$operation" == *[!a-z0-9_-]* || \
    -z "$phase" || "$phase" == *[!a-z0-9_-]* ]]; then
    die 64 "E_CHECKPOINT_VALUE: неверное значение checkpoint"
    return
  fi

  local checkpoint_path
  checkpoint_path="$(operation_checkpoint_path)"
  local checkpoint_parent
  checkpoint_parent="$(dirname "$checkpoint_path")"
  mkdir -p "$checkpoint_parent"
  chmod 0700 "$checkpoint_parent"
  python3 - "$checkpoint_path" "$operation" "$phase" <<'PY'
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

destination = Path(sys.argv[1])
temporary = destination.with_name(destination.name + ".tmp")
payload = {"operation": sys.argv[2], "phase": sys.argv[3]}
descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(payload, stream, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, destination)
    directory = os.open(destination.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
finally:
    try:
        temporary.unlink()
    except FileNotFoundError:
        pass
PY
}

clear_operation_checkpoint() {
  local checkpoint_path
  checkpoint_path="$(operation_checkpoint_path)"
  if [[ -f "$checkpoint_path" ]]; then
    rm -f -- "$checkpoint_path"
    sync -f "$(dirname "$checkpoint_path")" 2>/dev/null || true
  fi
}
