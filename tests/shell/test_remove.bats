#!/usr/bin/env bats

load "helpers/load.bash"

setup() {
  prepare_shell_test
  export EZOPENPN_ROOT_PREFIX="$TEST_ROOT"
  export EZOPENPN_LIBRARY_ROOT="${REPOSITORY_ROOT}/installer/lib"
  export EZOPENPN_TEST_EUID=0
  export EZOPENPN_TTY_INPUT_PATH="${BATS_TEST_TMPDIR}/tty-input"
  export EZOPENPN_TTY_OUTPUT_PATH="${BATS_TEST_TMPDIR}/tty-output"
  export TEST_REMOVE_SERVICE_BIN="${BATS_TEST_TMPDIR}/service-command"
  export TEST_REMOVE_FINAL_BACKUP_BIN="${BATS_TEST_TMPDIR}/final-backup-command"
  export TEST_REMOVE_EVENTS="${BATS_TEST_TMPDIR}/remove-events"
  export TEST_REMOVE_TIMESTAMP=20260831T120000Z
  export TEST_BACKUP_OWNER_UID
  TEST_BACKUP_OWNER_UID="$(id -u)"
  export TEST_COMMAND_LOG="${BATS_TEST_TMPDIR}/firewall-commands"
  export TEST_FIREWALL_BACKEND=ufw
  mkdir -p \
    "$TEST_ROOT/etc/ezopenpn" \
    "$TEST_ROOT/etc/systemd/system" \
    "$TEST_ROOT/etc/foreign" \
    "$TEST_ROOT/usr/local/bin" \
    "$TEST_ROOT/var/lib/ezopenpn/operations" \
    "$TEST_ROOT/var/backups/ezopenpn"
  printf '%s\n' 'services: {}' >"$TEST_ROOT/etc/ezopenpn/compose.yaml"
  : >"$TEST_ROOT/etc/ezopenpn/stack.env"
  printf '%s\n' \
    '{"admin_login":"owner","laboratory_mode":false,"public_ipv4":"203.0.113.10","version":"v0.1.0"}' \
    >"$TEST_ROOT/var/lib/ezopenpn/install.json"
  printf '%s\n' 'profile state' >"$TEST_ROOT/var/lib/ezopenpn/profiles.fixture"
  printf '%s\n' 'backup state' >"$TEST_ROOT/var/backups/ezopenpn/older.tar.gz"
  printf '%s\n' 'ufw|80/tcp' \
    >"$TEST_ROOT/var/lib/ezopenpn/operations/firewall.rules"
  printf '%s\n' unit >"$TEST_ROOT/etc/systemd/system/ezopenpn.service"
  printf '%s\n' cli >"$TEST_ROOT/usr/local/bin/ezopenpn"
  printf '%s\n' unrelated >"$TEST_ROOT/etc/foreign/keep"
  : >"$EZOPENPN_TTY_OUTPUT_PATH"
  : >"$TEST_REMOVE_EVENTS"
  : >"$TEST_COMMAND_LOG"
  cat >"$TEST_REMOVE_SERVICE_BIN" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$1" >>"$TEST_REMOVE_EVENTS"
SH
  cat >"$TEST_REMOVE_FINAL_BACKUP_BIN" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
archive="$1"
printf '%s\n' 'verified final archive' >"$archive"
printf '%s\n' 'verified checksum' >"${archive}.sha256"
chmod 0600 "$archive" "${archive}.sha256"
printf '%s\n' final-backup >>"$TEST_REMOVE_EVENTS"
SH
  chmod 0700 "$TEST_REMOVE_SERVICE_BIN" "$TEST_REMOVE_FINAL_BACKUP_BIN"
}

run_cli() {
  run bash "${REPOSITORY_ROOT}/installer/bin/ezopenpn" "$@"
}

assert_persistent_paths_exist() {
  [ -d "$TEST_ROOT/etc/ezopenpn" ]
  [ -d "$TEST_ROOT/var/lib/ezopenpn" ]
  [ -d "$TEST_ROOT/var/backups/ezopenpn" ]
  [ -f "$TEST_ROOT/var/lib/ezopenpn/profiles.fixture" ]
}

@test "uninstall leaves every persistent directory and prints reinstall command" {
  run_cli uninstall

  [ "$status" -eq 0 ]
  assert_persistent_paths_exist
  [ -f "$TEST_ROOT/usr/local/bin/ezopenpn" ]
  [ -f "$TEST_ROOT/etc/systemd/system/ezopenpn.service" ]
  [ -f "$TEST_ROOT/etc/foreign/keep" ]
  [ "$(cat "$TEST_REMOVE_EVENTS")" = $'disable\ndown' ]
  grep -Fq 'ufw --force delete allow 80/tcp comment EzOpenPN' "$TEST_COMMAND_LOG"
  [[ "$output" == *"sudo bash"* ]]
}

@test "purge with wrong confirmation removes nothing" {
  printf '%s\n' 'EzOpenPn' 'DELETE' >"$EZOPENPN_TTY_INPUT_PATH"

  run_cli purge

  [ "$status" -ne 0 ]
  assert_persistent_paths_exist
  [ -f "$TEST_ROOT/usr/local/bin/ezopenpn" ]
  [ ! -s "$TEST_COMMAND_LOG" ]
  [ "$(cat "$TEST_REMOVE_EVENTS")" = final-backup ]
}

@test "purge removes only the fixed roots after both exact confirmations" {
  printf '%s\n' 'EzOpenPN' 'DELETE' >"$EZOPENPN_TTY_INPUT_PATH"

  run_cli purge

  [ "$status" -eq 0 ]
  [ ! -e "$TEST_ROOT/etc/ezopenpn" ]
  [ ! -e "$TEST_ROOT/var/lib/ezopenpn" ]
  [ ! -e "$TEST_ROOT/var/backups/ezopenpn" ]
  [ ! -e "$TEST_ROOT/usr/local/bin/ezopenpn" ]
  [ ! -e "$TEST_ROOT/etc/systemd/system/ezopenpn.service" ]
  [ -f "$TEST_ROOT/var/backups/ezopenpn-final-20260831T120000Z.tar.gz" ]
  [ -f "$TEST_ROOT/var/backups/ezopenpn-final-20260831T120000Z.tar.gz.sha256" ]
  [ -f "$TEST_ROOT/etc/foreign/keep" ]
  [[ "$output" == *"ezopenpn-final-20260831T120000Z.tar.gz"* ]]
}

@test "real final archive is verified outside the removable backup root" {
  unset TEST_REMOVE_FINAL_BACKUP_BIN
  mkdir -p \
    "$TEST_ROOT/var/lib/ezopenpn/control" \
    "$TEST_ROOT/var/lib/ezopenpn/secrets" \
    "$TEST_ROOT/var/lib/ezopenpn/runtime/material" \
    "$TEST_ROOT/var/lib/ezopenpn/runtime/xray" \
    "$TEST_ROOT/var/lib/ezopenpn/runtime/hysteria" \
    "$TEST_ROOT/var/lib/ezopenpn/caddy/pki"
  printf '%s\n' control >"$TEST_ROOT/etc/ezopenpn/control.toml"
  printf '%s\n' edge >"$TEST_ROOT/etc/ezopenpn/Caddyfile"
  printf '%-32s' master >"$TEST_ROOT/var/lib/ezopenpn/secrets/master.key"
  printf '%-32s' api >"$TEST_ROOT/var/lib/ezopenpn/secrets/hysteria-api.key"
  printf '%-32s' obfs >"$TEST_ROOT/var/lib/ezopenpn/secrets/hysteria-obfs.key"
  printf '%s\n' '{}' \
    >"$TEST_ROOT/var/lib/ezopenpn/runtime/material/runtime-values.json"
  printf '%s\n' '{}' >"$TEST_ROOT/var/lib/ezopenpn/runtime/material/node.json"
  printf '%s\n' '{}' >"$TEST_ROOT/var/lib/ezopenpn/runtime/xray/config.json"
  printf '%s\n' 'listen: :8443' \
    >"$TEST_ROOT/var/lib/ezopenpn/runtime/hysteria/config.yaml"
  printf '%s\n' certificate >"$TEST_ROOT/var/lib/ezopenpn/caddy/pki/state.pem"
  chmod 0600 "$TEST_ROOT/var/lib/ezopenpn/secrets/"*.key
  python3 - "$TEST_ROOT/var/lib/ezopenpn/control/ezopenpn.sqlite3" <<'PY'
import sqlite3
import sys

with sqlite3.connect(sys.argv[1]) as connection:
    connection.execute("CREATE TABLE alembic_version (version_num TEXT NOT NULL)")
    connection.execute("INSERT INTO alembic_version VALUES ('0001_initial')")
    connection.execute("CREATE TABLE profiles (id TEXT PRIMARY KEY)")
    connection.execute("INSERT INTO profiles VALUES ('profile-one')")
PY
  printf '%s\n' wrong DELETE >"$EZOPENPN_TTY_INPUT_PATH"

  run_cli purge

  [ "$status" -eq 2 ]
  [ -f "$TEST_ROOT/var/backups/ezopenpn-final-20260831T120000Z.tar.gz" ]
  [ -f "$TEST_ROOT/var/backups/ezopenpn-final-20260831T120000Z.tar.gz.sha256" ]
  [ -d "$TEST_ROOT/var/backups/ezopenpn" ]
  [ ! -s "$TEST_REMOVE_EVENTS" ]
}

@test "uninstall refuses to hide an interrupted operation" {
  local checkpoint="$TEST_ROOT/var/lib/ezopenpn/operations/current.json"
  printf '%s\n' '{"operation":"upgrade","phase":"switching"}' >"$checkpoint"

  run_cli uninstall

  [ "$status" -ne 0 ]
  [ -f "$checkpoint" ]
  [ ! -s "$TEST_REMOVE_EVENTS" ]
  assert_persistent_paths_exist
}
