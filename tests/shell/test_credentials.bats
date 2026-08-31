#!/usr/bin/env bats

load "helpers/load.bash"

setup() {
  prepare_shell_test
  export EZOPENPN_TTY_INPUT_PATH="${BATS_TEST_TMPDIR}/tty-input"
  export EZOPENPN_TTY_OUTPUT_PATH="${BATS_TEST_TMPDIR}/tty-output"
  export TEST_CAPTURE_ROOT="${BATS_TEST_TMPDIR}/capture"
  mkdir -p "$TEST_CAPTURE_ROOT"
  : >"$EZOPENPN_TTY_OUTPUT_PATH"
  export TEST_CONTROL_BIN="${BATS_TEST_TMPDIR}/control-command"
  cat >"$TEST_CONTROL_BIN" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
mkdir -p "$TEST_CAPTURE_ROOT"
if [[ -r /proc/$$/cmdline ]]; then
  tr '\0' '\n' </proc/$$/cmdline >"$TEST_CAPTURE_ROOT/arguments"
else
  printf '%s\n' "$0" "$@" >"$TEST_CAPTURE_ROOT/arguments"
fi
env >"$TEST_CAPTURE_ROOT/environment"
cat >"$TEST_CAPTURE_ROOT/stdin"
SH
  chmod 0700 "$TEST_CONTROL_BIN"
  source "${REPOSITORY_ROOT}/installer/lib/common.sh"
  source "${REPOSITORY_ROOT}/installer/lib/credentials.sh"
}

@test "initial administrator secret reaches the child only on stdin" {
  local phrase='strong console phrase'
  printf '%s\n' owner "$phrase" "$phrase" >"$EZOPENPN_TTY_INPUT_PATH"

  initialize_admin_from_tty "$TEST_CONTROL_BIN"

  [ "$(cat "$TEST_CAPTURE_ROOT/stdin")" = "$phrase" ]
  grep -Fxq init-admin "$TEST_CAPTURE_ROOT/arguments"
  grep -Fxq owner "$TEST_CAPTURE_ROOT/arguments"
  ! grep -Fq "$phrase" "$TEST_CAPTURE_ROOT/arguments"
  ! grep -Fq "$phrase" "$TEST_CAPTURE_ROOT/environment"
  ! grep -Fq "$phrase" "$EZOPENPN_TTY_OUTPUT_PATH"
  [ -z "${ADMIN_PASSWORD+x}" ]
}

@test "mismatched confirmation never invokes the control command" {
  printf '%s\n' owner 'strong console phrase' 'different console phrase' \
    >"$EZOPENPN_TTY_INPUT_PATH"

  run initialize_admin_from_tty "$TEST_CONTROL_BIN"

  [ "$status" -eq 64 ]
  [[ "$output" == *"E_CREDENTIAL_CONFIRM"* ]]
  [ ! -e "$TEST_CAPTURE_ROOT/stdin" ]
}

@test "short secret is rejected before child execution" {
  printf '%s\n' owner short-value short-value >"$EZOPENPN_TTY_INPUT_PATH"

  run initialize_admin_from_tty "$TEST_CONTROL_BIN"

  [ "$status" -eq 64 ]
  [[ "$output" == *"E_CREDENTIAL_LENGTH"* ]]
  [ ! -e "$TEST_CAPTURE_ROOT/stdin" ]
}

@test "administrator login and secret must differ" {
  printf '%s\n' long-owner-name long-owner-name long-owner-name \
    >"$EZOPENPN_TTY_INPUT_PATH"

  run initialize_admin_from_tty "$TEST_CONTROL_BIN"

  [ "$status" -eq 64 ]
  [[ "$output" == *"E_CREDENTIAL_REUSE"* ]]
  [ ! -e "$TEST_CAPTURE_ROOT/stdin" ]
}
