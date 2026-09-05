#!/usr/bin/env bats

load "helpers/load.bash"
load "helpers/upgrade_fixture.bash"

setup() {
  prepare_upgrade_fixture
  export TEST_UPGRADE_BUNDLE_ROOT="$TEST_UPGRADE_CURRENT_BUNDLE"
}

@test "reinstall preserves profile and master key hashes" {
  local database="$TEST_ROOT/var/lib/ezopenpn/control/ezopenpn.sqlite3"
  local master="$TEST_ROOT/var/lib/ezopenpn/secrets/master.key"
  local before_database before_master
  before_database="$(upgrade_file_hash "$database")"
  before_master="$(upgrade_file_hash "$master")"

  run_upgrade_cli reinstall

  [ "$status" -eq 0 ]
  [ "$(upgrade_file_hash "$database")" = "$before_database" ]
  [ "$(upgrade_file_hash "$master")" = "$before_master" ]
  [ "$(readlink "$TEST_ROOT/etc/ezopenpn/current")" = releases/v0.1.0 ]
  [ "$(upgrade_state_version)" = v0.1.0 ]
  [ "$(cat "$TEST_UPGRADE_SERVICE_STATE")" = running ]
  [ "$(cat "$TEST_UPGRADE_EVENTS")" = $'pull\nprepare\nstop\nbackup\nmigrate\nstart\nhealth' ]
}

@test "reinstall replaces damaged release files while preserving data" {
  local database="$TEST_ROOT/var/lib/ezopenpn/control/ezopenpn.sqlite3"
  local before_database
  before_database="$(upgrade_file_hash "$database")"
  printf '%s\n' damaged \
    >"$TEST_ROOT/etc/ezopenpn/releases/v0.1.0/installer/lib/fixture.txt"

  run_upgrade_cli reinstall

  [ "$status" -eq 0 ]
  [ "$(cat "$TEST_ROOT/etc/ezopenpn/releases/v0.1.0/installer/lib/fixture.txt")" = \
    'library fixture' ]
  [ "$(upgrade_file_hash "$database")" = "$before_database" ]
}
