#!/usr/bin/env bats

load "helpers/load.bash"

setup() {
  prepare_shell_test
  export EZOPENPN_ROOT_PREFIX="$TEST_ROOT"
  export EZOPENPN_BUNDLE_ROOT="${BATS_TEST_TMPDIR}/bundle"
  export TEST_INSTALL_FLOW=1
  export TEST_INSTALL_EVENTS="${BATS_TEST_TMPDIR}/events"
  export TEST_MANAGED_SERVICES="${BATS_TEST_TMPDIR}/managed-services"
  export TEST_MANAGED_FIREWALL="${BATS_TEST_TMPDIR}/managed-firewall"
  mkdir -p "$EZOPENPN_BUNDLE_ROOT/deploy" "$EZOPENPN_BUNDLE_ROOT/installer"
  printf '%s\n' '{"version":"v0.1.0"}' >"$EZOPENPN_BUNDLE_ROOT/manifest.json"
  source "${REPOSITORY_ROOT}/installer/lib/common.sh"
  source "${REPOSITORY_ROOT}/installer/lib/state.sh"
  source "${REPOSITORY_ROOT}/installer/lib/lock.sh"
  source "${REPOSITORY_ROOT}/installer/lib/configure.sh"
  source "${REPOSITORY_ROOT}/installer/lib/install.sh"
}

@test "install reaches complete in the required dependency order" {
  run installer_main

  [ "$status" -eq 0 ]
  local expected
  expected=$'preflight\nbundle_verified\ndocker_ready\nfirewall_ready\nlayout_ready\ngateway_started\ncertificate_ready\ncontrol_migrated\nadmin_created\nruntimes_ready\nexternal_checks_passed\ninstall_complete'
  [ "$(cat "$TEST_INSTALL_EVENTS")" = "$expected" ]
  [[ "$output" == *"https://203.0.113.10:9443"* ]]
  [[ "$output" == *"sudo ezopenpn admin reset-password"* ]]
  [ -f "$EZOPENPN_STATE_ROOT/install.json" ]
  [ ! -e "$EZOPENPN_STATE_ROOT/operations/current.json" ]
}

@test "failed runtime health removes managed services and firewall rules" {
  export TEST_FAIL_PHASE=runtimes_ready

  run installer_main

  [ "$status" -eq 55 ]
  [ ! -e "$TEST_MANAGED_SERVICES" ]
  [ ! -e "$TEST_MANAGED_FIREWALL" ]
  [[ "$output" == *"E_INSTALL_PHASE"* ]]
  [ -f "$EZOPENPN_STATE_ROOT/operations/current.json" ]
}

@test "laboratory certificate requires both explicit files" {
  local certificate="${BATS_TEST_TMPDIR}/server.crt"
  printf '%s\n' placeholder >"$certificate"

  run installer_main --advanced-lab-certificate "$certificate"

  [ "$status" -eq 2 ]
  [ ! -e "$TEST_INSTALL_EVENTS" ]
  [ ! -e "$TEST_MANAGED_SERVICES" ]
  [ ! -e "$TEST_MANAGED_FIREWALL" ]
}

@test "laboratory pair must match the detected address and exact confirmation" {
  local certificate_root="${BATS_TEST_TMPDIR}/certificate"
  bash "${REPOSITORY_ROOT}/tests/compose/fixtures/test-ip-cert.sh" \
    "$certificate_root" 203.0.113.10
  INSTALL_LAB_CERTIFICATE="$certificate_root/server.crt"
  INSTALL_LAB_KEY="$certificate_root/server.key"
  INSTALL_LAB_MODE=1
  INSTALL_PUBLIC_IP=203.0.113.10
  export EZOPENPN_TTY_INPUT_PATH="${BATS_TEST_TMPDIR}/lab-input"
  export EZOPENPN_TTY_OUTPUT_PATH="${BATS_TEST_TMPDIR}/lab-output"
  printf '%s\n' LAB >"$EZOPENPN_TTY_INPUT_PATH"
  : >"$EZOPENPN_TTY_OUTPUT_PATH"

  run _validate_laboratory_pair

  [ "$status" -eq 0 ]
  grep -Fq 'Введите LAB' "$EZOPENPN_TTY_OUTPUT_PATH"
}

@test "an interrupted install resumes through idempotent phases" {
  write_operation_checkpoint install gateway_started

  run installer_main

  [ "$status" -eq 0 ]
  grep -Fxq install_complete "$TEST_INSTALL_EVENTS"
  [ ! -e "$EZOPENPN_STATE_ROOT/operations/current.json" ]
}

@test "systemd unit owns only the fixed application compose project" {
  local unit="${REPOSITORY_ROOT}/installer/systemd/ezopenpn.service"

  [ -f "$unit" ]
  grep -Fq 'WorkingDirectory=/etc/ezopenpn/current' "$unit"
  grep -Fq -- '--project-name ezopenpn' "$unit"
  grep -Fq 'RemainAfterExit=yes' "$unit"
  ! grep -Fq 'docker.sock' "$unit"
}

@test "verified bundle entrypoint runs the same installer flow" {
  run bash "${REPOSITORY_ROOT}/installer/installer-main.sh"

  [ "$status" -eq 0 ]
  grep -Fxq install_complete "$TEST_INSTALL_EVENTS"
  [[ "$output" == *"https://203.0.113.10:9443"* ]]
}

@test "release installation is atomic and an identical rerun is stable" {
  printf '%s\n' 'services: {}' >"$EZOPENPN_BUNDLE_ROOT/deploy/compose.yaml"
  printf '%s\n' '#!/usr/bin/env bash' \
    >"$EZOPENPN_BUNDLE_ROOT/installer/installer-main.sh"
  printf '%s\n' good.example >"$EZOPENPN_BUNDLE_ROOT/installer/targets.txt"
  mkdir -p "$TEST_ROOT/etc/ezopenpn/releases"
  INSTALL_VERSION=v0.1.0

  _install_release_files
  local first_target
  first_target="$(readlink "$TEST_ROOT/etc/ezopenpn/current")"
  _install_release_files

  [ "$first_target" = 'releases/v0.1.0' ]
  [ "$(readlink "$TEST_ROOT/etc/ezopenpn/current")" = "$first_target" ]
  [ -f "$TEST_ROOT/etc/ezopenpn/releases/v0.1.0/deploy/compose.yaml" ]
  [ ! -e "$TEST_ROOT/etc/ezopenpn/current/current.tmp" ]
}

@test "bundle manifest supplies only immutable stack images" {
  local digest
  digest="$(printf 'b%.0s' {1..64})"
  printf '%s\n' \
    "{\"version\":\"v0.1.0\",\"images\":{\"control\":\"example.invalid/control@sha256:${digest}\",\"xray\":\"example.invalid/xray@sha256:${digest}\",\"hysteria\":\"example.invalid/hysteria@sha256:${digest}\",\"gateway\":\"example.invalid/gateway@sha256:${digest}\",\"cert-sync\":\"example.invalid/cert-sync@sha256:${digest}\"}}" \
    >"$EZOPENPN_BUNDLE_ROOT/manifest.json"
  mkdir -p "$TEST_ROOT/etc/ezopenpn"
  export TEST_CHOWN_LOG="${BATS_TEST_TMPDIR}/chown.log"

  _verify_install_bundle
  INSTALL_PUBLIC_IP=203.0.113.10
  _install_stack_environment

  grep -Fqx "CONTROL_IMAGE=example.invalid/control@sha256:${digest}" \
    "$TEST_ROOT/etc/ezopenpn/stack.env"
  grep -Fqx "CERT_SYNC_IMAGE=example.invalid/cert-sync@sha256:${digest}" \
    "$TEST_ROOT/etc/ezopenpn/stack.env"
  ! grep -Eq 'IMAGE=.*:latest$' "$TEST_ROOT/etc/ezopenpn/stack.env"
}
