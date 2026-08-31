#!/usr/bin/env bats

load "helpers/load.bash"

setup() {
  prepare_shell_test
  export EZOPENPN_ROOT_PREFIX="$TEST_ROOT"
  export EZOPENPN_LIBRARY_ROOT="${REPOSITORY_ROOT}/installer/lib"
  export EZOPENPN_TEST_EUID=0
  mkdir -p "$TEST_ROOT/etc/ezopenpn" "$TEST_ROOT/var/lib/ezopenpn"
  printf '%s\n' \
    '{"admin_login":"owner","laboratory_mode":false,"public_ipv4":"203.0.113.10","version":"v0.1.0"}' \
    >"$TEST_ROOT/var/lib/ezopenpn/install.json"
  printf '%s\n' 'services: {}' >"$TEST_ROOT/etc/ezopenpn/compose.yaml"
  : >"$TEST_ROOT/etc/ezopenpn/stack.env"
}

run_cli() {
  run bash "${REPOSITORY_ROOT}/installer/bin/ezopenpn" "$@"
}

@test "unknown service log request is rejected" {
  run_cli logs host

  [ "$status" -eq 2 ]
  [[ "$output" == *"control, xray, hysteria, gateway, cert-sync"* ]]
}

@test "unknown top level command is rejected with usage" {
  run_cli launch

  [ "$status" -eq 2 ]
  [[ "$output" == *"Использование:"* ]]
}

@test "status reports an unavailable installation with exit three" {
  rm "$TEST_ROOT/var/lib/ezopenpn/install.json"

  run_cli status

  [ "$status" -eq 3 ]
  [[ "$output" == *"E_INSTALL_UNAVAILABLE"* ]]
}

@test "log numeric options are bounded before compose execution" {
  run_cli logs control --tail unlimited

  [ "$status" -eq 2 ]
  [[ "$output" == *"E_LOG_ARGUMENT"* ]]
}
