#!/usr/bin/env bats

load "helpers/load.bash"

setup() {
  prepare_shell_test
  source "${REPOSITORY_ROOT}/installer/lib/common.sh"
  source "${REPOSITORY_ROOT}/installer/lib/state.sh"
}

@test "safe path rejects root and unresolved text" {
  run require_absolute_safe_path "/"
  [ "$status" -ne 0 ]

  run require_absolute_safe_path '${MISSING_VALUE}'
  [ "$status" -ne 0 ]
}

@test "safe path accepts a fixed application directory" {
  run require_absolute_safe_path "/var/lib/ezopenpn"
  [ "$status" -eq 0 ]
}

@test "checkpoint is replaced with valid deterministic JSON" {
  write_operation_checkpoint "install" "preflight"
  write_operation_checkpoint "install" "layout_ready"

  run python3 - "${EZOPENPN_STATE_ROOT}/operations/current.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    checkpoint = json.load(stream)
assert checkpoint == {"operation": "install", "phase": "layout_ready"}
PY
  [ "$status" -eq 0 ]
  [ ! -e "${EZOPENPN_STATE_ROOT}/operations/current.json.tmp" ]
}

@test "root and controlling terminal checks have stable failures" {
  EZOPENPN_TEST_EUID=1000 run require_root
  [ "$status" -eq 20 ]
  [[ "$output" == *"E_PREFLIGHT_ROOT"* ]]

  rm "${EZOPENPN_TTY_PATH}"
  run require_tty
  [ "$status" -eq 21 ]
  [[ "$output" == *"E_PREFLIGHT_TTY"* ]]
}
