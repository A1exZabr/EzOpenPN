#!/usr/bin/env bats

load "helpers/load.bash"

setup() {
  prepare_shell_test
  export EZOPENPN_TEST_EUID=0
  export TEST_UNAME_M=x86_64
  export TEST_SYSTEMD=1
  export TEST_MEMORY_KIB=2097152
  export TEST_DISK_KIB=8388608
  export TEST_TIME_SYNC=yes
  export TEST_PUBLIC_IP_A=203.0.113.10
  export TEST_PUBLIC_IP_B=203.0.113.10
  export TEST_IP_ADDR_OUTPUT='2: eth0    inet 203.0.113.10/24 scope global eth0'
  export TEST_NETWORK_OK=1
  export TEST_SS_OUTPUT=""
  export TEST_DOCKER_PS_OUTPUT=""
  export TEST_FIREWALL_STATE=none
  export EZOPENPN_OS_RELEASE_PATH="${REPOSITORY_ROOT}/tests/shell/fixtures/os-release/ubuntu-24.04"
  source "${REPOSITORY_ROOT}/installer/lib/common.sh"
  source "${REPOSITORY_ROOT}/installer/lib/preflight.sh"
}

assert_preflight_ok() {
  run run_preflight
  [ "$status" -eq 0 ]
  [[ "$output" == *'"ok":true'* ]]
  [[ "$output" == *'"public_ipv4":"203.0.113.10"'* ]]
}

@test "all supported operating system fixtures pass" {
  local fixture
  for fixture in ubuntu-22.04 ubuntu-24.04 debian-12 debian-13; do
    export EZOPENPN_OS_RELEASE_PATH="${REPOSITORY_ROOT}/tests/shell/fixtures/os-release/${fixture}"
    assert_preflight_ok
  done
}

@test "accurate HTTPS clock is accepted before the sync service reports ready" {
  export TEST_TIME_SYNC=no
  export TEST_HTTPS_DATE='Mon, 31 Aug 2026 16:18:00 GMT'
  export TEST_NOW_EPOCH=1788193380

  assert_preflight_ok
}

@test "clock skew over five minutes is rejected" {
  export TEST_TIME_SYNC=no
  export TEST_HTTPS_DATE='Mon, 31 Aug 2026 16:18:00 GMT'
  export TEST_NOW_EPOCH=1788193381

  run run_preflight

  [ "$status" -eq 23 ]
  [[ "$output" == *"E_PREFLIGHT_TIME"* ]]
}

@test "unsupported architecture fails before mutation" {
  export TEST_UNAME_M=aarch64

  run run_preflight

  [ "$status" -eq 20 ]
  [[ "$output" == *"E_PREFLIGHT_ARCH"* ]]
  [ ! -e "${TEST_ROOT}/etc/ezopenpn" ]
}

@test "occupied tcp port reports owning process" {
  export TEST_SS_OUTPUT='LISTEN 0 128 0.0.0.0:443 0.0.0.0:* users:(("caddy",pid=123,fd=7))'

  run run_preflight

  [ "$status" -eq 24 ]
  [[ "$output" == *"443/tcp"* ]]
  [[ "$output" == *"caddy"* ]]
  [ ! -e "${TEST_ROOT}/etc/ezopenpn" ]
}

@test "different public address observations are rejected" {
  export TEST_PUBLIC_IP_B=198.51.100.8

  run run_preflight

  [ "$status" -eq 22 ]
  [[ "$output" == *"E_PREFLIGHT_PUBLIC_IP"* ]]
}

@test "foreign running containers are rejected" {
  export TEST_DOCKER_PS_OUTPUT='foreign-project database-1'

  run run_preflight

  [ "$status" -eq 25 ]
  [[ "$output" == *"E_PREFLIGHT_CONTAINERS"* ]]
}

@test "an existing installation enters maintenance mode" {
  printf '%s\n' '{"version":"0.1.0"}' >"${EZOPENPN_STATE_ROOT}/install.json"
  export TEST_SS_OUTPUT=$'LISTEN 0 128 0.0.0.0:443 0.0.0.0:* users:(("docker-proxy",pid=123,fd=7))\nUNCONN 0 0 0.0.0.0:443 0.0.0.0:* users:(("docker-proxy",pid=124,fd=7))'
  export TEST_DOCKER_PS_OUTPUT=$'ezopenpn ezopenpn-xray-1\nezopenpn ezopenpn-hysteria-1'

  run run_preflight

  [ "$status" -eq 0 ]
  [[ "$output" == *'"mode":"maintenance"'* ]]
}

@test "installer may resume its own validated checkpoint" {
  mkdir -p "$EZOPENPN_STATE_ROOT/operations"
  printf '%s\n' '{"operation":"install","phase":"gateway_started"}' \
    >"$EZOPENPN_STATE_ROOT/operations/current.json"

  EZOPENPN_ALLOW_INTERRUPTED_INSTALL=1 run run_preflight

  [ "$status" -eq 0 ]
  [[ "$output" == *'"mode":"maintenance"'* ]]
}
