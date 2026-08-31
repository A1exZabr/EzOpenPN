#!/usr/bin/env bats

load "helpers/load.bash"

setup() {
  prepare_shell_test
  export EZOPENPN_ROOT_PREFIX="$TEST_ROOT"
  export TEST_OS_ID=debian
  export TEST_OS_CODENAME=bookworm
  export TEST_DOCKER_READY=0
  export TEST_DOCKER_INSTALL=1
  export TEST_COMMAND_LOG="${BATS_TEST_TMPDIR}/commands.log"
  export TEST_APT_SOURCE="${TEST_ROOT}/etc/apt/sources.list.d/docker.sources"
  source "${REPOSITORY_ROOT}/installer/lib/common.sh"
  source "${REPOSITORY_ROOT}/installer/lib/docker.sh"
}

@test "docker install uses official repository for detected distribution" {
  run ensure_docker_engine

  [ "$status" -eq 0 ]
  grep -q "https://download.docker.com/linux/debian" "$TEST_APT_SOURCE"
  grep -q "Suites: bookworm" "$TEST_APT_SOURCE"
  grep -q \
    "docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin" \
    "$TEST_COMMAND_LOG"
}

@test "compatible existing engine is preserved" {
  export TEST_DOCKER_READY=1

  run ensure_docker_engine

  [ "$status" -eq 0 ]
  [ ! -e "$TEST_APT_SOURCE" ]
  [ ! -s "$TEST_COMMAND_LOG" ]
}

@test "unknown distribution is rejected without apt mutation" {
  export TEST_OS_ID=alpine

  run ensure_docker_engine

  [ "$status" -ne 0 ]
  [[ "$output" == *"E_DOCKER_OS"* ]]
  [ ! -e "$TEST_APT_SOURCE" ]
}
