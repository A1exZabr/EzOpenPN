make_upgrade_bundle() {
  local version="$1"
  local destination="$2"
  mkdir -p \
    "$destination/deploy" \
    "$destination/installer/bin" \
    "$destination/installer/lib" \
    "$destination/installer/systemd"
  printf '%s\n' 'services: {}' >"$destination/deploy/compose.yaml"
  printf '%s\n' '#!/usr/bin/env bash' >"$destination/installer/installer-main.sh"
  printf '%s\n' '#!/usr/bin/env bash' >"$destination/installer/bin/ezopenpn"
  printf '%s\n' '[Unit]' >"$destination/installer/systemd/ezopenpn.service"
  printf '%s\n' 'library fixture' >"$destination/installer/lib/fixture.txt"
  python3 - "$version" "$destination/manifest.json" <<'PY'
import json
import sys
from pathlib import Path

version = sys.argv[1]
digest = "a" * 64
images = {
    name: f"example.invalid/ezopenpn/{name}@sha256:{digest}"
    for name in ("control", "xray", "hysteria", "gateway", "cert-sync")
}
Path(sys.argv[2]).write_text(
    json.dumps({"images": images, "version": version}, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY
}

prepare_upgrade_fixture() {
  prepare_shell_test
  export EZOPENPN_ROOT_PREFIX="$TEST_ROOT"
  export EZOPENPN_LIBRARY_ROOT="${REPOSITORY_ROOT}/installer/lib"
  export EZOPENPN_TEST_EUID=0
  export TEST_UPGRADE_PREFLIGHT=1
  export TEST_UPGRADE_EVENTS="${BATS_TEST_TMPDIR}/upgrade-events"
  export TEST_UPGRADE_SERVICE_STATE="${BATS_TEST_TMPDIR}/service-state"
  export TEST_UPGRADE_BACKUP_BIN="${BATS_TEST_TMPDIR}/backup-command"
  export TEST_UPGRADE_SERVICE_BIN="${BATS_TEST_TMPDIR}/service-command"
  export TEST_UPGRADE_PULL_BIN="${BATS_TEST_TMPDIR}/pull-command"
  export TEST_UPGRADE_PREPARE_BIN="${BATS_TEST_TMPDIR}/prepare-command"
  export TEST_UPGRADE_MIGRATE_BIN="${BATS_TEST_TMPDIR}/migrate-command"
  export TEST_UPGRADE_PREIMAGE_ROOT="${BATS_TEST_TMPDIR}/preimages"
  export TEST_UPGRADE_CURRENT_BUNDLE="${BATS_TEST_TMPDIR}/bundle-v0.1.0"
  mkdir -p \
    "$TEST_ROOT/etc/ezopenpn/releases" \
    "$TEST_ROOT/var/lib/ezopenpn/control" \
    "$TEST_ROOT/var/lib/ezopenpn/secrets" \
    "$TEST_ROOT/var/lib/ezopenpn/runtime/material" \
    "$TEST_ROOT/var/lib/ezopenpn/runtime/xray" \
    "$TEST_ROOT/var/lib/ezopenpn/runtime/hysteria" \
    "$TEST_ROOT/var/lib/ezopenpn/operations" \
    "$TEST_ROOT/var/backups/ezopenpn" \
    "$TEST_UPGRADE_PREIMAGE_ROOT"
  make_upgrade_bundle v0.1.0 "$TEST_UPGRADE_CURRENT_BUNDLE"
  cp -R "$TEST_UPGRADE_CURRENT_BUNDLE" \
    "$TEST_ROOT/etc/ezopenpn/releases/v0.1.0"
  ln -s releases/v0.1.0 "$TEST_ROOT/etc/ezopenpn/current"
  printf '%s\n' 'profile-database-original' \
    >"$TEST_ROOT/var/lib/ezopenpn/control/ezopenpn.sqlite3"
  printf '%-32s' 'master-key-original' \
    >"$TEST_ROOT/var/lib/ezopenpn/secrets/master.key"
  printf '%-32s' 'secondary-api-original' \
    >"$TEST_ROOT/var/lib/ezopenpn/secrets/hysteria-api.key"
  printf '%-32s' 'secondary-obfs-original' \
    >"$TEST_ROOT/var/lib/ezopenpn/secrets/hysteria-obfs.key"
  printf '%s\n' 'control-v1' >"$TEST_ROOT/etc/ezopenpn/control.toml"
  printf '%s\n' 'edge-v1' >"$TEST_ROOT/etc/ezopenpn/Caddyfile"
  printf '%s\n' 'services: {}' >"$TEST_ROOT/etc/ezopenpn/compose.yaml"
  printf '%s\n' \
    'PUBLIC_IP=203.0.113.10' \
    'CONTROL_IMAGE=example.invalid/ezopenpn/control@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
    >"$TEST_ROOT/etc/ezopenpn/stack.env"
  printf '%s\n' '{"runtime":"material"}' \
    >"$TEST_ROOT/var/lib/ezopenpn/runtime/material/runtime-values.json"
  printf '%s\n' '{"node":"material"}' \
    >"$TEST_ROOT/var/lib/ezopenpn/runtime/material/node.json"
  printf '%s\n' 'xray-v1' >"$TEST_ROOT/var/lib/ezopenpn/runtime/xray/config.json"
  printf '%s\n' 'hysteria-v1' \
    >"$TEST_ROOT/var/lib/ezopenpn/runtime/hysteria/config.yaml"
  printf '%s\n' \
    '{"admin_login":"owner","installed_at":"2026-08-31T00:00:00+00:00","laboratory_mode":false,"public_ipv4":"203.0.113.10","version":"v0.1.0"}' \
    >"$TEST_ROOT/var/lib/ezopenpn/install.json"
  chmod 0600 "$TEST_ROOT/var/lib/ezopenpn/secrets/"*.key
  : >"$TEST_UPGRADE_EVENTS"
  printf '%s\n' running >"$TEST_UPGRADE_SERVICE_STATE"

  cat >"$TEST_UPGRADE_BACKUP_BIN" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  create)
    [[ "${TEST_UPGRADE_BACKUP_FAIL:-0}" != 1 ]] || exit 1
    [[ "$(cat "$TEST_UPGRADE_SERVICE_STATE")" == stopped ]] || exit 1
    destination="$TEST_UPGRADE_PREIMAGE_ROOT/preimage-$RANDOM"
    mkdir -p "$destination"
    cp "$EZOPENPN_ROOT_PREFIX/var/lib/ezopenpn/control/ezopenpn.sqlite3" "$destination/database"
    cp "$EZOPENPN_ROOT_PREFIX/var/lib/ezopenpn/secrets/master.key" "$destination/master"
    cp "$EZOPENPN_ROOT_PREFIX/etc/ezopenpn/stack.env" "$destination/stack.env"
    cp "$EZOPENPN_ROOT_PREFIX/etc/ezopenpn/compose.yaml" "$destination/compose.yaml"
    printf '%s\n' "$destination"
    printf '%s\n' backup >>"$TEST_UPGRADE_EVENTS"
    ;;
  restore)
    source_root="$2"
    cp "$source_root/database" "$EZOPENPN_ROOT_PREFIX/var/lib/ezopenpn/control/ezopenpn.sqlite3"
    cp "$source_root/master" "$EZOPENPN_ROOT_PREFIX/var/lib/ezopenpn/secrets/master.key"
    cp "$source_root/stack.env" "$EZOPENPN_ROOT_PREFIX/etc/ezopenpn/stack.env"
    cp "$source_root/compose.yaml" "$EZOPENPN_ROOT_PREFIX/etc/ezopenpn/compose.yaml"
    printf '%s\n' restore >>"$TEST_UPGRADE_EVENTS"
    ;;
  *) exit 2 ;;
esac
SH
  cat >"$TEST_UPGRADE_SERVICE_BIN" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$1" >>"$TEST_UPGRADE_EVENTS"
case "$1" in
  stop) printf '%s\n' stopped >"$TEST_UPGRADE_SERVICE_STATE" ;;
  start) printf '%s\n' running >"$TEST_UPGRADE_SERVICE_STATE" ;;
  health)
    [[ "$(cat "$TEST_UPGRADE_SERVICE_STATE")" == running ]] || exit 1
    current="$(readlink "$EZOPENPN_ROOT_PREFIX/etc/ezopenpn/current")"
    if [[ "${TEST_OLD_CONTROL_HEALTH:-}" == fail && "$current" == releases/v0.1.0 ]]; then
      exit 1
    fi
    if [[ "${TEST_NEW_CONTROL_HEALTH:-}" == fail && "$current" == releases/v0.2.0 ]]; then
      exit 1
    fi
    ;;
  *) exit 2 ;;
esac
SH
  cat >"$TEST_UPGRADE_PULL_BIN" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' pull >>"$TEST_UPGRADE_EVENTS"
if [[ "${TEST_PROFILE_REVOKED_DURING_PULL:-0}" == 1 ]]; then
  printf '%s\n' profile-revoked-during-pull \
    >"$EZOPENPN_ROOT_PREFIX/var/lib/ezopenpn/control/ezopenpn.sqlite3"
fi
SH
  cat >"$TEST_UPGRADE_PREPARE_BIN" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
stage="$2"
mkdir -p "$stage/etc" "$stage/runtime/xray" "$stage/runtime/hysteria"
cp "$EZOPENPN_ROOT_PREFIX/etc/ezopenpn/control.toml" "$stage/etc/control.toml"
cp "$EZOPENPN_ROOT_PREFIX/etc/ezopenpn/Caddyfile" "$stage/etc/Caddyfile"
cp "$1/deploy/compose.yaml" "$stage/etc/compose.yaml"
cp "$EZOPENPN_ROOT_PREFIX/etc/ezopenpn/stack.env" "$stage/stack.env"
cp "$EZOPENPN_ROOT_PREFIX/var/lib/ezopenpn/runtime/xray/config.json" \
  "$stage/runtime/xray/config.json"
cp "$EZOPENPN_ROOT_PREFIX/var/lib/ezopenpn/runtime/hysteria/config.yaml" \
  "$stage/runtime/hysteria/config.yaml"
printf '%s\n' prepare >>"$TEST_UPGRADE_EVENTS"
SH
  cat >"$TEST_UPGRADE_MIGRATE_BIN" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' migrate >>"$TEST_UPGRADE_EVENTS"
if [[ "${TEST_MIGRATE_MUTATE:-0}" == 1 ]]; then
  printf '%s\n' 'database-mutated-by-new-release' \
    >"$EZOPENPN_ROOT_PREFIX/var/lib/ezopenpn/control/ezopenpn.sqlite3"
fi
SH
  chmod 0700 \
    "$TEST_UPGRADE_BACKUP_BIN" \
    "$TEST_UPGRADE_SERVICE_BIN" \
    "$TEST_UPGRADE_PULL_BIN" \
    "$TEST_UPGRADE_PREPARE_BIN" \
    "$TEST_UPGRADE_MIGRATE_BIN"
}

upgrade_file_hash() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

upgrade_state_version() {
  python3 - "$TEST_ROOT/var/lib/ezopenpn/install.json" <<'PY'
import json
import sys

print(json.load(open(sys.argv[1], encoding="utf-8"))["version"])
PY
}

run_upgrade_cli() {
  run bash "${REPOSITORY_ROOT}/installer/bin/ezopenpn" "$@"
}
