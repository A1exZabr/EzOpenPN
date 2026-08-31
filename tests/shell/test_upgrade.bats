#!/usr/bin/env bats

# shellcheck disable=SC2030,SC2031

load "helpers/load.bash"
load "helpers/upgrade_fixture.bash"

setup() {
  prepare_upgrade_fixture
  export TEST_UPGRADE_BUNDLE_ROOT="${BATS_TEST_TMPDIR}/bundle-v0.2.0"
  make_upgrade_bundle v0.2.0 "$TEST_UPGRADE_BUNDLE_ROOT"
}

@test "healthy update switches release without changing persistent material" {
  local database="$TEST_ROOT/var/lib/ezopenpn/control/ezopenpn.sqlite3"
  local master="$TEST_ROOT/var/lib/ezopenpn/secrets/master.key"
  local before_database before_master
  before_database="$(upgrade_file_hash "$database")"
  before_master="$(upgrade_file_hash "$master")"

  run_upgrade_cli update

  [ "$status" -eq 0 ]
  [ "$(readlink "$TEST_ROOT/etc/ezopenpn/current")" = releases/v0.2.0 ]
  [ "$(upgrade_state_version)" = v0.2.0 ]
  [ "$(upgrade_file_hash "$database")" = "$before_database" ]
  [ "$(upgrade_file_hash "$master")" = "$before_master" ]
  [ "$(cat "$TEST_UPGRADE_SERVICE_STATE")" = running ]
}

@test "failed new health restores old release database and image lock" {
  local database="$TEST_ROOT/var/lib/ezopenpn/control/ezopenpn.sqlite3"
  local before_database before_environment
  before_database="$(upgrade_file_hash "$database")"
  before_environment="$(upgrade_file_hash "$TEST_ROOT/etc/ezopenpn/stack.env")"
  export TEST_NEW_CONTROL_HEALTH=fail
  export TEST_MIGRATE_MUTATE=1

  run_upgrade_cli update

  [ "$status" -ne 0 ]
  [ "$(readlink "$TEST_ROOT/etc/ezopenpn/current")" = releases/v0.1.0 ]
  [ "$(upgrade_state_version)" = v0.1.0 ]
  [ "$(upgrade_file_hash "$database")" = "$before_database" ]
  [ "$(upgrade_file_hash "$TEST_ROOT/etc/ezopenpn/stack.env")" = "$before_environment" ]
  [ "$(cat "$TEST_UPGRADE_SERVICE_STATE")" = running ]
  [[ "$(cat "$TEST_UPGRADE_EVENTS")" == *$'restore\nstart\nhealth'* ]]
}

@test "update rejects a lower version before backup or service changes" {
  export TEST_UPGRADE_BUNDLE_ROOT="${BATS_TEST_TMPDIR}/bundle-v0.0.9"
  make_upgrade_bundle v0.0.9 "$TEST_UPGRADE_BUNDLE_ROOT"

  run_upgrade_cli update

  [ "$status" -ne 0 ]
  [ "$(readlink "$TEST_ROOT/etc/ezopenpn/current")" = releases/v0.1.0 ]
  [ ! -s "$TEST_UPGRADE_EVENTS" ]
}

@test "next command recovers an interrupted switched transaction first" {
  local preimage stage journal
  preimage="$("$TEST_UPGRADE_BACKUP_BIN" create)"
  stage="$TEST_ROOT/var/lib/ezopenpn/operations/.stage.interrupted"
  mkdir -p "$stage"
  cp -R "$TEST_ROOT/etc/ezopenpn/releases/v0.1.0" "$stage/release-before"
  cp -R "$TEST_UPGRADE_BUNDLE_ROOT" "$TEST_ROOT/etc/ezopenpn/releases/v0.2.0"
  unlink "$TEST_ROOT/etc/ezopenpn/current"
  ln -s releases/v0.2.0 "$TEST_ROOT/etc/ezopenpn/current"
  printf '%s\n' interrupted-migration \
    >"$TEST_ROOT/var/lib/ezopenpn/control/ezopenpn.sqlite3"
  journal="$TEST_ROOT/var/lib/ezopenpn/operations/upgrade-transaction.json"
  python3 - "$journal" "$preimage" "$stage" <<'PY'
import json
import sys
from pathlib import Path

Path(sys.argv[1]).write_text(
    json.dumps(
        {
            "current_version": "v0.1.0",
            "old_current": "releases/v0.1.0",
            "phase": "migrated",
            "preimage": sys.argv[2],
            "stage": sys.argv[3],
            "target_version": "v0.2.0",
        },
        sort_keys=True,
    )
    + "\n",
    encoding="utf-8",
)
PY
  chmod 0600 "$journal"
  export TEST_UPGRADE_BUNDLE_ROOT="$TEST_UPGRADE_CURRENT_BUNDLE"
  : >"$TEST_UPGRADE_EVENTS"

  run_upgrade_cli update

  [ "$status" -eq 0 ]
  [ "$(readlink "$TEST_ROOT/etc/ezopenpn/current")" = releases/v0.1.0 ]
  [ "$(cat "$TEST_ROOT/var/lib/ezopenpn/control/ezopenpn.sqlite3")" = \
    profile-database-original ]
  [ ! -e "$journal" ]
  [ ! -e "$stage" ]
  [ "$(cat "$TEST_UPGRADE_SERVICE_STATE")" = running ]
  [ "$(cat "$TEST_UPGRADE_EVENTS")" = $'stop\nrestore\nstart\nhealth' ]
}

@test "foreign operation checkpoint is never cleared by update" {
  local checkpoint="$TEST_ROOT/var/lib/ezopenpn/operations/current.json"
  printf '%s\n' '{"operation":"install","phase":"gateway_started"}' >"$checkpoint"

  run_upgrade_cli update

  [ "$status" -ne 0 ]
  [ -f "$checkpoint" ]
  [ ! -s "$TEST_UPGRADE_EVENTS" ]
  [ "$(readlink "$TEST_ROOT/etc/ezopenpn/current")" = releases/v0.1.0 ]
}
