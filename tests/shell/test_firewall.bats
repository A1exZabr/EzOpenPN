#!/usr/bin/env bats

load "helpers/load.bash"

setup() {
  prepare_shell_test
  export EZOPENPN_ROOT_PREFIX="$TEST_ROOT"
  export TEST_COMMAND_LOG="${BATS_TEST_TMPDIR}/commands.log"
  export TEST_FIREWALL_BACKEND=ufw
  export TEST_UFW_STATUS='22/tcp ALLOW Anywhere # foreign-ssh-rule'
  source "${REPOSITORY_ROOT}/installer/lib/common.sh"
  source "${REPOSITORY_ROOT}/installer/lib/firewall.sh"
}

@test "firewall rollback removes only rules created by this operation" {
  apply_firewall_rules
  rollback_firewall_rules

  grep -q "ufw allow 80/tcp comment EzOpenPN" "$TEST_COMMAND_LOG"
  grep -q "ufw --force delete allow 80/tcp comment EzOpenPN" "$TEST_COMMAND_LOG"
  [[ "$TEST_UFW_STATUS" == *"foreign-ssh-rule"* ]]
  [ ! -s "${EZOPENPN_STATE_ROOT}/operations/firewall.rules" ]
  ! grep -q "delete allow 22/tcp" "$TEST_COMMAND_LOG"
}

@test "inactive firewall remains inactive" {
  export TEST_FIREWALL_BACKEND=none

  run apply_firewall_rules

  [ "$status" -eq 0 ]
  [ ! -s "$TEST_COMMAND_LOG" ]
}

@test "repeated apply does not duplicate managed rules" {
  apply_firewall_rules
  apply_firewall_rules

  [ "$(grep -c "ufw allow 443/udp" "$TEST_COMMAND_LOG")" -eq 1 ]
}

@test "firewalld uses a dedicated service and rollback" {
  export TEST_FIREWALL_BACKEND=firewalld

  apply_firewall_rules
  rollback_firewall_rules

  grep -q "firewall-cmd --permanent --add-service=ezopenpn" "$TEST_COMMAND_LOG"
  grep -q "firewall-cmd --permanent --remove-service=ezopenpn" "$TEST_COMMAND_LOG"
  [ ! -e "${TEST_ROOT}/etc/firewalld/services/ezopenpn.xml" ]
}
