#!/usr/bin/env bats

load "helpers/load.bash"

setup() {
  prepare_shell_test
  export EZOPENPN_TEST_HOST=admin@example.test
  export EZOPENPN_TEST_SSH_BIN="${BATS_TEST_TMPDIR}/ssh-command"
  export EZOPENPN_TEST_INSTALL_COMMAND='one-command-install'
  export TEST_VM_SSH_LOG="${BATS_TEST_TMPDIR}/ssh.log"
  cat >"$EZOPENPN_TEST_SSH_BIN" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf 'CALL' >>"$TEST_VM_SSH_LOG"
for argument in "$@"; do
  printf ' <%s>' "$argument" >>"$TEST_VM_SSH_LOG"
done
printf '\n' >>"$TEST_VM_SSH_LOG"
if [[ ! -t 0 ]]; then
  bytes="$(wc -c | tr -d ' ')"
  printf 'STDIN <%s>\n' "$bytes" >>"$TEST_VM_SSH_LOG"
fi
SH
  chmod 0700 "$EZOPENPN_TEST_SSH_BIN"
  : >"$TEST_VM_SSH_LOG"
}

@test "vm runner installs twice around capture and preservation checks" {
  run bash "${REPOSITORY_ROOT}/tests/vm/run-install-twice.sh"

  [ "$status" -eq 0 ]
  [ "$(grep -c '^CALL' "$TEST_VM_SSH_LOG")" -eq 4 ]
  [ "$(grep -c 'one-command-install' "$TEST_VM_SSH_LOG")" -eq 2 ]
  grep -Fq '<sudo bash -s -- capture>' "$TEST_VM_SSH_LOG"
  grep -Fq '<sudo bash -s -- verify>' "$TEST_VM_SSH_LOG"
  [ "$(grep -Ec '^STDIN <[1-9][0-9]*>$' "$TEST_VM_SSH_LOG")" -eq 2 ]
}

@test "vm runner rejects an ssh target beginning with an option" {
  export EZOPENPN_TEST_HOST='-oProxyCommand=unsafe'

  run bash "${REPOSITORY_ROOT}/tests/vm/run-install-twice.sh"

  [ "$status" -eq 2 ]
  [ ! -s "$TEST_VM_SSH_LOG" ]
}
