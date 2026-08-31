REPOSITORY_ROOT="$(cd "${BATS_TEST_DIRNAME}/../.." && pwd -P)"
export REPOSITORY_ROOT

prepare_shell_test() {
  export TEST_ROOT="${BATS_TEST_TMPDIR}/host"
  export EZOPENPN_STATE_ROOT="${TEST_ROOT}/var/lib/ezopenpn"
  export EZOPENPN_RUN_ROOT="${TEST_ROOT}/run"
  export EZOPENPN_TTY_PATH="${TEST_ROOT}/dev/tty"
  mkdir -p "${TEST_ROOT}/dev" "${EZOPENPN_STATE_ROOT}" "${EZOPENPN_RUN_ROOT}"
  : >"${EZOPENPN_TTY_PATH}"
}
