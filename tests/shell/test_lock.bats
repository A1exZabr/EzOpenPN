#!/usr/bin/env bats

load "helpers/load.bash"

setup() {
  prepare_shell_test
  source "${REPOSITORY_ROOT}/installer/lib/common.sh"
  source "${REPOSITORY_ROOT}/installer/lib/lock.sh"
}

teardown() {
  release_operation_lock
}

@test "second mutating command cannot acquire the operation lock" {
  acquire_operation_lock "install"

  run bash -c \
    'source "$REPOSITORY_ROOT/installer/lib/common.sh"; source "$REPOSITORY_ROOT/installer/lib/lock.sh"; acquire_operation_lock update'

  [ "$status" -eq 73 ]
  [[ "$output" == *"E_OPERATION_LOCKED"* ]]
}

@test "released operation lock can be acquired again" {
  acquire_operation_lock "install"
  release_operation_lock

  run acquire_operation_lock "doctor"
  [ "$status" -eq 0 ]
}
