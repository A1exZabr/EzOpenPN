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

@test "failed update preserves a profile revocation completed during image download" {
  export TEST_PROFILE_REVOKED_DURING_PULL=1
  export TEST_NEW_CONTROL_HEALTH=fail
  export TEST_MIGRATE_MUTATE=1

  run_upgrade_cli update

  [ "$status" -ne 0 ]
  [ "$(cat "$TEST_ROOT/var/lib/ezopenpn/control/ezopenpn.sqlite3")" = \
    profile-revoked-during-pull ]
  [ "$(cat "$TEST_UPGRADE_SERVICE_STATE")" = running ]
  [[ "$(cat "$TEST_UPGRADE_EVENTS")" == *$'stop\nbackup\nmigrate'* ]]
}

@test "failed snapshot resumes the old release without switching or restoring its database" {
  export TEST_UPGRADE_BACKUP_FAIL=1
  export TEST_PROFILE_REVOKED_DURING_PULL=1

  run_upgrade_cli update

  [ "$status" -ne 0 ]
  [ "$(upgrade_state_version)" = v0.1.0 ]
  [ "$(cat "$TEST_ROOT/var/lib/ezopenpn/control/ezopenpn.sqlite3")" = \
    profile-revoked-during-pull ]
  [ "$(cat "$TEST_UPGRADE_SERVICE_STATE")" = running ]
  [ "$(cat "$TEST_UPGRADE_EVENTS")" = $'pull\nprepare\nstop\nstart\nhealth' ]
  [ ! -e "$TEST_ROOT/var/lib/ezopenpn/operations/upgrade-transaction.json" ]
}

@test "prepared interruption resumes the old stack without reverting database changes" {
  local stage="$TEST_ROOT/var/lib/ezopenpn/operations/.stage.prepared"
  mkdir -p "$stage"
  source "${REPOSITORY_ROOT}/installer/lib/common.sh"
  source "${REPOSITORY_ROOT}/installer/lib/state.sh"
  source "${REPOSITORY_ROOT}/installer/lib/backup.sh"
  source "${REPOSITORY_ROOT}/installer/lib/upgrade.sh"
  UPGRADE_CURRENT_VERSION=v0.1.0
  UPGRADE_TARGET_VERSION=v0.2.0
  UPGRADE_OLD_CURRENT=releases/v0.1.0
  UPGRADE_STAGE="$stage"
  UPGRADE_PREIMAGE=""
  _upgrade_write_journal prepared
  printf '%s\n' stopped >"$TEST_UPGRADE_SERVICE_STATE"
  printf '%s\n' profile-revoked-before-stop \
    >"$TEST_ROOT/var/lib/ezopenpn/control/ezopenpn.sqlite3"
  export TEST_UPGRADE_BUNDLE_ROOT="$TEST_UPGRADE_CURRENT_BUNDLE"

  run_upgrade_cli update

  [ "$status" -eq 0 ]
  [ "$(cat "$TEST_ROOT/var/lib/ezopenpn/control/ezopenpn.sqlite3")" = \
    profile-revoked-before-stop ]
  [ "$(cat "$TEST_UPGRADE_SERVICE_STATE")" = running ]
  [ "$(cat "$TEST_UPGRADE_EVENTS")" = $'start\nhealth' ]
  [ ! -d "$stage" ]
  [ ! -e "$TEST_ROOT/var/lib/ezopenpn/operations/upgrade-transaction.json" ]
}

@test "unsuccessful resume after snapshot failure keeps its recovery journal for the next command" {
  export TEST_UPGRADE_BACKUP_FAIL=1
  export TEST_OLD_CONTROL_HEALTH=fail
  export TEST_PROFILE_REVOKED_DURING_PULL=1

  run_upgrade_cli update

  [ "$status" -ne 0 ]
  [ -f "$TEST_ROOT/var/lib/ezopenpn/operations/upgrade-transaction.json" ]
  [[ "$output" == *E_UPGRADE_RECOVERY* ]]
  unset TEST_UPGRADE_BACKUP_FAIL TEST_OLD_CONTROL_HEALTH
  export TEST_UPGRADE_BUNDLE_ROOT="$TEST_UPGRADE_CURRENT_BUNDLE"
  : >"$TEST_UPGRADE_EVENTS"

  run_upgrade_cli update

  [ "$status" -eq 0 ]
  [ "$(cat "$TEST_ROOT/var/lib/ezopenpn/control/ezopenpn.sqlite3")" = \
    profile-revoked-during-pull ]
  [ "$(cat "$TEST_UPGRADE_EVENTS")" = $'start\nhealth' ]
  [ ! -e "$TEST_ROOT/var/lib/ezopenpn/operations/upgrade-transaction.json" ]
}

@test "next command recovers an interrupted switched transaction first" {
  local preimage stage journal
  printf '%s\n' stopped >"$TEST_UPGRADE_SERVICE_STATE"
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

@test "laboratory reinstall keeps the laboratory gateway policy" {
  local stage="${BATS_TEST_TMPDIR}/laboratory-stage"
  mkdir -p "$stage/etc" "$TEST_UPGRADE_BUNDLE_ROOT/installer/lab"
  printf '%s\n' 'production gateway' >"$stage/etc/Caddyfile"
  printf '%s\n' 'laboratory gateway' \
    >"$TEST_UPGRADE_BUNDLE_ROOT/installer/lab/Caddyfile"
  python3 - "$TEST_ROOT/var/lib/ezopenpn/install.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
value = json.loads(path.read_text(encoding="utf-8"))
value["laboratory_mode"] = True
path.write_text(json.dumps(value) + "\n", encoding="utf-8")
PY
  source "${REPOSITORY_ROOT}/installer/lib/backup.sh"
  source "${REPOSITORY_ROOT}/installer/lib/upgrade.sh"
  UPGRADE_BUNDLE_ROOT="$TEST_UPGRADE_BUNDLE_ROOT"

  run _upgrade_apply_laboratory_gateway "$stage"

  [ "$status" -eq 0 ]
  [ "$(cat "$stage/etc/Caddyfile")" = 'laboratory gateway' ]
}
