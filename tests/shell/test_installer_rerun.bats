#!/usr/bin/env bats

load "helpers/load.bash"
load "helpers/upgrade_fixture.bash"

setup() {
  prepare_upgrade_fixture
  export EZOPENPN_BUNDLE_ROOT="$REPOSITORY_ROOT"
  export TEST_UPGRADE_BUNDLE_ROOT="${BATS_TEST_TMPDIR}/bundle-v0.2.0"
  make_upgrade_bundle v0.2.0 "$TEST_UPGRADE_BUNDLE_ROOT"
  source "$REPOSITORY_ROOT/installer/lib/common.sh"
  source "$REPOSITORY_ROOT/installer/lib/state.sh"
  source "$REPOSITORY_ROOT/installer/lib/lock.sh"
  source "$REPOSITORY_ROOT/installer/lib/install.sh"
  require_root() { :; }
  require_tty() { :; }
  # No real host operations: the legacy path must never stop this installation.
  run_preflight() { printf '%s\n' '{"ok":false,"diagnostic":"E_PREFLIGHT_NETWORK"}'; return 22; }
  systemctl() {
    case "$*" in
      'enable --now ezopenpn.service') printf '%s\n' running >"$TEST_UPGRADE_SERVICE_STATE" ;;
      *) printf '%s\n' stopped >"$TEST_UPGRADE_SERVICE_STATE" ;;
    esac
  }
  _install_compose() { printf '%s\n' stopped >"$TEST_UPGRADE_SERVICE_STATE"; }
  rollback_firewall_rules() { :; }
  apply_firewall_rules() {
    if [[ "${TEST_REQUIRE_INSTALL_LOCK:-0}" == 1 ]] && \
      (acquire_operation_lock competing >/dev/null 2>&1); then
      return 1
    fi
    printf '%s\n' restored >"$BATS_TEST_TMPDIR/firewall-restored"
  }
}

@test "rerunning installer with failed preflight preserves the running installation" {
  export TEST_UPGRADE_PREFLIGHT=0
  local before
  before="$(upgrade_file_hash "$TEST_ROOT/etc/ezopenpn/stack.env")"

  run installer_main

  [ "$status" -ne 0 ]
  [ "$(cat "$TEST_UPGRADE_SERVICE_STATE")" = running ]
  [ "$(upgrade_file_hash "$TEST_ROOT/etc/ezopenpn/stack.env")" = "$before" ]
  [ ! -s "$TEST_UPGRADE_EVENTS" ]
  [[ "$output" == *E_UPGRADE_PREFLIGHT* ]]
}

@test "rerunning installer with failed image pull preserves the old version" {
  export TEST_UPGRADE_PULL_BIN=/bin/false
  local before
  before="$(upgrade_file_hash "$TEST_ROOT/var/lib/ezopenpn/control/ezopenpn.sqlite3")"

  run installer_main

  [ "$status" -ne 0 ]
  [ "$(cat "$TEST_UPGRADE_SERVICE_STATE")" = running ]
  [ "$(upgrade_state_version)" = v0.1.0 ]
  [ "$(upgrade_file_hash "$TEST_ROOT/var/lib/ezopenpn/control/ezopenpn.sqlite3")" = "$before" ]
  [ "$(cat "$TEST_UPGRADE_EVENTS")" = health ]
  [[ "$output" == *E_UPGRADE_PREPARE* ]]
}

@test "rerunning current installer is a no-op and returns the panel address" {
  export TEST_REQUIRE_INSTALL_LOCK=1
  export TEST_UPGRADE_BUNDLE_ROOT="$TEST_UPGRADE_CURRENT_BUNDLE"
  export TEST_HEALTH_CONTROL=healthy TEST_HEALTH_XRAY=healthy
  export TEST_HEALTH_HYSTERIA=healthy TEST_HEALTH_GATEWAY=healthy TEST_HEALTH_CERT_SYNC=healthy
  export TEST_CERTIFICATE_EXPIRY=2099-01-01T00:00:00Z TEST_ACTIVE_PROFILES=0 TEST_PANEL_READY=1

  run installer_main

  [ "$status" -eq 0 ]
  [ "$(cat "$TEST_UPGRADE_EVENTS")" = health ]
  [ "$(cat "$TEST_UPGRADE_SERVICE_STATE")" = running ]
  [[ "$output" == *"https://203.0.113.10:9443"* ]]
}

@test "rerunning installer after uninstall resumes the preserved stack" {
  export TEST_UPGRADE_BUNDLE_ROOT="$TEST_UPGRADE_CURRENT_BUNDLE"
  export TEST_HEALTH_CONTROL=healthy TEST_HEALTH_XRAY=healthy
  export TEST_HEALTH_HYSTERIA=healthy TEST_HEALTH_GATEWAY=healthy TEST_HEALTH_CERT_SYNC=healthy
  export TEST_CERTIFICATE_EXPIRY=2099-01-01T00:00:00Z TEST_ACTIVE_PROFILES=0 TEST_PANEL_READY=1
  printf '%s\n' stopped >"$TEST_UPGRADE_SERVICE_STATE"

  run installer_main

  [ "$status" -eq 0 ]
  [ "$(cat "$TEST_UPGRADE_SERVICE_STATE")" = running ]
  [ -f "$BATS_TEST_TMPDIR/firewall-restored" ]
  [ "$(upgrade_state_version)" = v0.1.0 ]
}

@test "rerunning after uninstall restores the old stack before backing up a newer release" {
  export TEST_HEALTH_CONTROL=healthy TEST_HEALTH_XRAY=healthy
  export TEST_HEALTH_HYSTERIA=healthy TEST_HEALTH_GATEWAY=healthy TEST_HEALTH_CERT_SYNC=healthy
  export TEST_CERTIFICATE_EXPIRY=2099-01-01T00:00:00Z TEST_ACTIVE_PROFILES=0 TEST_PANEL_READY=1
  printf '%s\n' stopped >"$TEST_UPGRADE_SERVICE_STATE"

  run installer_main

  [ "$status" -eq 0 ]
  [ "$(cat "$TEST_UPGRADE_SERVICE_STATE")" = running ]
  [ "$(upgrade_state_version)" = v0.2.0 ]
}
