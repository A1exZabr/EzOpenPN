#!/usr/bin/env bats

load "helpers/load.bash"

setup() {
  prepare_shell_test
  export EZOPENPN_ROOT_PREFIX="$TEST_ROOT"
  export EZOPENPN_LIBRARY_ROOT="${REPOSITORY_ROOT}/installer/lib"
  export EZOPENPN_TEST_EUID=0
  export TEST_BACKUP_OWNER_UID
  TEST_BACKUP_OWNER_UID="$(id -u)"
  export TEST_BACKUP_CONTROL_BIN="${BATS_TEST_TMPDIR}/control-command"
  export TEST_BACKUP_SERVICE_BIN="${BATS_TEST_TMPDIR}/service-command"
  export TEST_BACKUP_EVENTS="${BATS_TEST_TMPDIR}/service-events"
  export TEST_BACKUP_SERVICE_STATE="${BATS_TEST_TMPDIR}/service-state"
  mkdir -p \
    "$TEST_ROOT/etc/ezopenpn" \
    "$TEST_ROOT/var/lib/ezopenpn/control" \
    "$TEST_ROOT/var/lib/ezopenpn/secrets" \
    "$TEST_ROOT/var/lib/ezopenpn/runtime/material" \
    "$TEST_ROOT/var/lib/ezopenpn/runtime/xray" \
    "$TEST_ROOT/var/lib/ezopenpn/runtime/hysteria" \
    "$TEST_ROOT/var/lib/ezopenpn/caddy/pki" \
    "$TEST_ROOT/var/backups/ezopenpn"
  printf '%s\n' 'control configuration' >"$TEST_ROOT/etc/ezopenpn/control.toml"
  printf '%s\n' 'edge configuration' >"$TEST_ROOT/etc/ezopenpn/Caddyfile"
  printf '%s\n' 'services: {}' >"$TEST_ROOT/etc/ezopenpn/compose.yaml"
  printf '%s\n' 'PUBLIC_IP=203.0.113.10' >"$TEST_ROOT/etc/ezopenpn/stack.env"
  printf '%s\n' \
    '{"admin_login":"owner","laboratory_mode":false,"public_ipv4":"203.0.113.10","version":"v0.1.0"}' \
    >"$TEST_ROOT/var/lib/ezopenpn/install.json"
  printf '%-32s' 'master-secret' >"$TEST_ROOT/var/lib/ezopenpn/secrets/master.key"
  printf '%-32s' 'secondary-api-secret' \
    >"$TEST_ROOT/var/lib/ezopenpn/secrets/hysteria-api.key"
  printf '%-32s' 'secondary-obfs-secret' \
    >"$TEST_ROOT/var/lib/ezopenpn/secrets/hysteria-obfs.key"
  printf '%s\n' '{"runtime":"values"}' \
    >"$TEST_ROOT/var/lib/ezopenpn/runtime/material/runtime-values.json"
  printf '%s\n' '{"node":"private-material"}' \
    >"$TEST_ROOT/var/lib/ezopenpn/runtime/material/node.json"
  printf '%s\n' '{"inbounds":[]}' \
    >"$TEST_ROOT/var/lib/ezopenpn/runtime/xray/config.json"
  printf '%s\n' 'listen: :8443' \
    >"$TEST_ROOT/var/lib/ezopenpn/runtime/hysteria/config.yaml"
  printf '%s\n' 'certificate state' \
    >"$TEST_ROOT/var/lib/ezopenpn/caddy/pki/state.pem"
  chmod 0600 "$TEST_ROOT/var/lib/ezopenpn/secrets/"*.key
  python3 - "$TEST_ROOT/var/lib/ezopenpn/control/ezopenpn.sqlite3" <<'PY'
import sqlite3
import sys

with sqlite3.connect(sys.argv[1]) as connection:
    connection.execute("CREATE TABLE alembic_version (version_num TEXT NOT NULL)")
    connection.execute("INSERT INTO alembic_version VALUES ('0001_initial')")
    connection.execute(
        "CREATE TABLE profiles (id TEXT PRIMARY KEY, wrapped_profile_key BLOB NOT NULL)"
    )
    connection.execute(
        "INSERT INTO profiles VALUES (?, ?)", ("profile-one", b"encrypted-original")
    )
PY
  cat >"$TEST_BACKUP_CONTROL_BIN" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
command="$1"
shift
container_path="${2:-}"
host_path="$EZOPENPN_ROOT_PREFIX/var/lib/ezopenpn/control/$(basename "$container_path")"
case "$command" in
  backup-database)
    python3 - "$EZOPENPN_ROOT_PREFIX/var/lib/ezopenpn/control/ezopenpn.sqlite3" "$host_path" <<'PY'
import sqlite3
import sys

with sqlite3.connect(sys.argv[1]) as source, sqlite3.connect(sys.argv[2]) as target:
    source.backup(target)
PY
    chmod 0600 "$host_path"
    printf '%s\n' '{"quick_check":"ok","schema_version":"0001_initial"}'
    ;;
  verify-database)
    python3 - "$host_path" <<'PY'
import sqlite3
import sys

with sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True) as connection:
    quick = connection.execute("PRAGMA quick_check").fetchone()
    schema = connection.execute("SELECT version_num FROM alembic_version").fetchone()
raise SystemExit(0 if quick == ("ok",) and schema == ("0001_initial",) else 1)
PY
    ;;
  *) exit 2 ;;
esac
SH
  cat >"$TEST_BACKUP_SERVICE_BIN" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$1" >>"$TEST_BACKUP_EVENTS"
case "$1" in
  stop) printf '%s\n' stopped >"$TEST_BACKUP_SERVICE_STATE" ;;
  start) printf '%s\n' running >"$TEST_BACKUP_SERVICE_STATE" ;;
  health)
    [[ "$(cat "$TEST_BACKUP_SERVICE_STATE")" == running ]]
    if [[ "${TEST_BACKUP_HEALTH_FAIL_ONCE:-0}" == 1 && \
      ! -e "${TEST_BACKUP_HEALTH_MARKER:-}" ]]; then
      : >"$TEST_BACKUP_HEALTH_MARKER"
      exit 1
    fi
    [[ "${TEST_BACKUP_HEALTH_FAIL:-0}" != 1 ]]
    ;;
  *) exit 2 ;;
esac
SH
  chmod 0700 "$TEST_BACKUP_CONTROL_BIN" "$TEST_BACKUP_SERVICE_BIN"
  printf '%s\n' running >"$TEST_BACKUP_SERVICE_STATE"
  : >"$TEST_BACKUP_EVENTS"
}

run_cli() {
  run bash "${REPOSITORY_ROOT}/installer/bin/ezopenpn" "$@"
}

newest_archive() {
  find "$TEST_ROOT/var/backups/ezopenpn" -maxdepth 1 -type f -name '*.tar.gz' \
    -print | sort | tail -n 1
}

database_value() {
  python3 - "$TEST_ROOT/var/lib/ezopenpn/control/ezopenpn.sqlite3" <<'PY'
import sqlite3
import sys

with sqlite3.connect(sys.argv[1]) as connection:
    print(connection.execute("SELECT hex(wrapped_profile_key) FROM profiles").fetchone()[0])
PY
}

rewrite_manifest_schema() {
  python3 - "$1" <<'PY'
import hashlib
import io
import json
import os
import tarfile
import tempfile
import sys
from pathlib import Path

archive = Path(sys.argv[1])
members = []
with tarfile.open(archive, "r:gz") as source:
    for member in source.getmembers():
        data = source.extractfile(member).read() if member.isfile() else None
        if member.name == "manifest.json":
            manifest = json.loads(data)
            manifest["schema_version"] = "future_schema"
            data = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
            member.size = len(data)
        members.append((member, data))
descriptor, temporary_name = tempfile.mkstemp(dir=archive.parent)
os.close(descriptor)
temporary = Path(temporary_name)
with tarfile.open(temporary, "w:gz") as target:
    for member, data in members:
        target.addfile(member, io.BytesIO(data) if data is not None else None)
os.replace(temporary, archive)
digest = hashlib.sha256(archive.read_bytes()).hexdigest()
archive.with_name(archive.name + ".sha256").write_text(
    f"{digest}  {archive.name}\n", encoding="utf-8"
)
PY
}

@test "backup creates a private verified archive" {
  run_cli backup

  [ "$status" -eq 0 ]
  local archive
  archive="$(newest_archive)"
  [ -f "$archive" ]
  [ -f "${archive}.sha256" ]
  [ "$(stat -f '%Lp' "$archive")" = 600 ]
  [ "$(stat -f '%Lp' "${archive}.sha256")" = 600 ]
  [[ "$output" == *"$archive"* ]]
  [ "$(cat "$TEST_BACKUP_SERVICE_STATE")" = running ]
}

@test "backup restore round trip preserves profile and server material" {
  local original_database original_secret archive
  original_database="$(database_value)"
  original_secret="$(cat "$TEST_ROOT/var/lib/ezopenpn/secrets/master.key")"
  run_cli backup
  [ "$status" -eq 0 ]
  archive="$(newest_archive)"
  python3 - "$TEST_ROOT/var/lib/ezopenpn/control/ezopenpn.sqlite3" <<'PY'
import sqlite3
import sys

with sqlite3.connect(sys.argv[1]) as connection:
    connection.execute("UPDATE profiles SET wrapped_profile_key = ?", (b"changed",))
PY
  printf '%-32s' changed-secret >"$TEST_ROOT/var/lib/ezopenpn/secrets/master.key"
  printf '%s\n' changed >"$TEST_ROOT/var/lib/ezopenpn/caddy/pki/state.pem"
  : >"$TEST_BACKUP_EVENTS"

  run_cli restore "$archive"

  [ "$status" -eq 0 ]
  [ "$(database_value)" = "$original_database" ]
  [ "$(cat "$TEST_ROOT/var/lib/ezopenpn/secrets/master.key")" = "$original_secret" ]
  [ "$(cat "$TEST_ROOT/var/lib/ezopenpn/caddy/pki/state.pem")" = 'certificate state' ]
  [ "$(cat "$TEST_BACKUP_EVENTS")" = $'stop\nstart\nhealth' ]
}

@test "restore rejects an archive with a changed manifest before stopping" {
  run_cli backup
  [ "$status" -eq 0 ]
  local archive before
  archive="$(newest_archive)"
  before="$(database_value)"
  rewrite_manifest_schema "$archive"
  : >"$TEST_BACKUP_EVENTS"

  run_cli restore "$archive"

  [ "$status" -ne 0 ]
  [ "$(database_value)" = "$before" ]
  [ ! -s "$TEST_BACKUP_EVENTS" ]
  [ "$(cat "$TEST_BACKUP_SERVICE_STATE")" = running ]
}

@test "restore rejects parent traversal without creating a file" {
  local archive="$TEST_ROOT/var/backups/ezopenpn/traversal.tar.gz"
  python3 - "$archive" <<'PY'
import hashlib
import io
import tarfile
import sys
from pathlib import Path

archive = Path(sys.argv[1])
with tarfile.open(archive, "w:gz") as stream:
    info = tarfile.TarInfo("../outside")
    info.size = 6
    stream.addfile(info, io.BytesIO(b"unsafe"))
digest = hashlib.sha256(archive.read_bytes()).hexdigest()
archive.with_name(archive.name + ".sha256").write_text(
    f"{digest}  {archive.name}\n", encoding="utf-8"
)
archive.chmod(0o600)
archive.with_name(archive.name + ".sha256").chmod(0o600)
PY

  run_cli restore "$archive"

  [ "$status" -ne 0 ]
  [ ! -e "$TEST_ROOT/var/backups/outside" ]
  [ ! -s "$TEST_BACKUP_EVENTS" ]
}

@test "failed restored health returns the exact pre-restore state" {
  run_cli backup
  [ "$status" -eq 0 ]
  local archive changed_database changed_secret
  archive="$(newest_archive)"
  python3 - "$TEST_ROOT/var/lib/ezopenpn/control/ezopenpn.sqlite3" <<'PY'
import sqlite3
import sys

with sqlite3.connect(sys.argv[1]) as connection:
    connection.execute("UPDATE profiles SET wrapped_profile_key = ?", (b"preimage",))
PY
  printf '%-32s' preimage-secret >"$TEST_ROOT/var/lib/ezopenpn/secrets/master.key"
  changed_database="$(database_value)"
  changed_secret="$(cat "$TEST_ROOT/var/lib/ezopenpn/secrets/master.key")"
  export TEST_BACKUP_HEALTH_FAIL_ONCE=1
  export TEST_BACKUP_HEALTH_MARKER="${BATS_TEST_TMPDIR}/health-failed"
  : >"$TEST_BACKUP_EVENTS"

  run_cli restore "$archive"

  [ "$status" -ne 0 ]
  [ "$(database_value)" = "$changed_database" ]
  [ "$(cat "$TEST_ROOT/var/lib/ezopenpn/secrets/master.key")" = "$changed_secret" ]
  [ "$(cat "$TEST_BACKUP_SERVICE_STATE")" = running ]
  [ "$(cat "$TEST_BACKUP_EVENTS")" = $'stop\nstart\nhealth\nstop\nstart\nhealth' ]
}
