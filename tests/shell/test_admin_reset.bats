#!/usr/bin/env bats

load "helpers/load.bash"

setup() {
  prepare_shell_test
  export EZOPENPN_ROOT_PREFIX="$TEST_ROOT"
  export EZOPENPN_LIBRARY_ROOT="${REPOSITORY_ROOT}/installer/lib"
  export EZOPENPN_TEST_EUID=0
  export EZOPENPN_TTY_INPUT_PATH="${BATS_TEST_TMPDIR}/tty-input"
  export EZOPENPN_TTY_OUTPUT_PATH="${BATS_TEST_TMPDIR}/tty-output"
  export TEST_CAPTURE_ROOT="${BATS_TEST_TMPDIR}/capture"
  export TEST_ADMIN_CONTROL_BIN="${BATS_TEST_TMPDIR}/control-command"
  mkdir -p "$TEST_CAPTURE_ROOT" "$TEST_ROOT/var/lib/ezopenpn/control"
  printf '%s\n' \
    '{"admin_login":"owner","laboratory_mode":false,"public_ipv4":"203.0.113.10","version":"v0.1.0"}' \
    >"$TEST_ROOT/var/lib/ezopenpn/install.json"
  printf '%s\n' 'unchanged profile material' \
    >"$TEST_ROOT/var/lib/ezopenpn/control/profiles.fixture"
  : >"$EZOPENPN_TTY_OUTPUT_PATH"
  cat >"$TEST_ADMIN_CONTROL_BIN" <<'SH'
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
: >"$TEST_CAPTURE_ROOT/sessions-revoked"
SH
  chmod 0700 "$TEST_ADMIN_CONTROL_BIN"
}

file_hash() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

run_cli() {
  run bash "${REPOSITORY_ROOT}/installer/bin/ezopenpn" "$@"
}

@test "password reset passes the value on stdin and preserves profiles" {
  local phrase='new strong console phrase'
  local profile="$TEST_ROOT/var/lib/ezopenpn/control/profiles.fixture"
  local before
  before="$(file_hash "$profile")"
  printf '%s\n' "$phrase" "$phrase" >"$EZOPENPN_TTY_INPUT_PATH"

  run_cli admin reset-password

  [ "$status" -eq 0 ]
  local cli_output="$output"
  [ "$(cat "$TEST_CAPTURE_ROOT/stdin")" = "$phrase" ]
  grep -Fxq reset-password "$TEST_CAPTURE_ROOT/arguments"
  grep -Fxq -- --password-stdin "$TEST_CAPTURE_ROOT/arguments"
  run grep -Fq "$phrase" "$TEST_CAPTURE_ROOT/arguments"
  [ "$status" -eq 1 ]
  run grep -Fq "$phrase" "$TEST_CAPTURE_ROOT/environment"
  [ "$status" -eq 1 ]
  [ -e "$TEST_CAPTURE_ROOT/sessions-revoked" ]
  [ "$(file_hash "$profile")" = "$before" ]
  [[ "$cli_output" == *"Все активные сеансы завершены"* ]]
}

@test "mismatched reset confirmation invokes nothing" {
  printf '%s\n' 'new strong console phrase' 'different console phrase' \
    >"$EZOPENPN_TTY_INPUT_PATH"

  run_cli admin reset-password

  [ "$status" -eq 2 ]
  [[ "$output" == *"E_CREDENTIAL_CONFIRM"* ]]
  [ ! -e "$TEST_CAPTURE_ROOT/stdin" ]
}
