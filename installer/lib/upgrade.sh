#!/usr/bin/env bash

upgrade_library_directory="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${upgrade_library_directory}/release.sh"
# shellcheck disable=SC1091
source "${upgrade_library_directory}/configure.sh"
# shellcheck disable=SC1091
source "${upgrade_library_directory}/install.sh"
unset upgrade_library_directory

UPGRADE_BUNDLE_ROOT=""
UPGRADE_FETCH_ROOT=""
UPGRADE_TARGET_VERSION=""
UPGRADE_CURRENT_VERSION=""
UPGRADE_OLD_CURRENT=""
UPGRADE_PREIMAGE=""
UPGRADE_STAGE=""
UPGRADE_PHASE=""

_upgrade_state_path() {
  _backup_path /var/lib/ezopenpn/install.json
}

_upgrade_state_field() {
  local field="$1"
  python3 - "$(_upgrade_state_path)" "$field" <<'PY'
import json
import sys
from pathlib import Path

value = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
result = value.get(sys.argv[2])
if isinstance(result, bool):
    print("true" if result else "false")
elif isinstance(result, str):
    print(result)
else:
    raise SystemExit(1)
PY
}

_upgrade_current_link() {
  local current
  current="$(_backup_path /etc/ezopenpn/current)"
  [[ -L "$current" ]] || return 1
  local target
  target="$(readlink "$current")"
  [[ "$target" =~ ^releases/v[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  printf '%s\n' "$target"
}

_upgrade_compare_versions() {
  python3 - "$1" "$2" <<'PY'
import re
import sys

pattern = re.compile(r"v([0-9]+)\.([0-9]+)\.([0-9]+)")
values = []
for raw in sys.argv[1:]:
    match = pattern.fullmatch(raw)
    if match is None:
        raise SystemExit(2)
    values.append(tuple(int(part) for part in match.groups()))
print(-1 if values[0] < values[1] else 1 if values[0] > values[1] else 0)
PY
}

_upgrade_cleanup_directory() {
  local path="${1:-}"
  local expected_parent="$2"
  local prefix="$3"
  [[ -n "$path" && -d "$path" && ! -L "$path" ]] || return 0
  python3 - "$path" "$expected_parent" "$prefix" <<'PY'
import shutil
import stat
import sys
from pathlib import Path

path = Path(sys.argv[1]).absolute()
parent = Path(sys.argv[2]).absolute()
if path.parent != parent or not path.name.startswith(sys.argv[3]):
    raise SystemExit(1)
status = path.lstat()
if stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
    raise SystemExit(1)
shutil.rmtree(path)
PY
}

_upgrade_cleanup_fetch() {
  if [[ -n "$UPGRADE_FETCH_ROOT" ]]; then
    _upgrade_cleanup_directory "$UPGRADE_FETCH_ROOT" /tmp ezopenpn-upgrade. || true
    UPGRADE_FETCH_ROOT=""
  fi
}

_upgrade_cleanup_stage() {
  if [[ -n "$UPGRADE_STAGE" ]]; then
    local operations_root
    operations_root="$(_backup_path /var/lib/ezopenpn/operations)"
    _upgrade_cleanup_directory "$UPGRADE_STAGE" "$operations_root" .stage. || true
    UPGRADE_STAGE=""
  fi
}

_upgrade_fetch_verified_bundle() {
  local mode="$1"
  local current_version="$2"
  if [[ -n "${TEST_UPGRADE_BUNDLE_ROOT:-}" ]]; then
    if [[ "$TEST_UPGRADE_BUNDLE_ROOT" != /* || \
      ! -d "$TEST_UPGRADE_BUNDLE_ROOT" || -L "$TEST_UPGRADE_BUNDLE_ROOT" ]]; then
      return 1
    fi
    UPGRADE_BUNDLE_ROOT="$TEST_UPGRADE_BUNDLE_ROOT"
    EZOPENPN_BUNDLE_ROOT="$UPGRADE_BUNDLE_ROOT"
    export EZOPENPN_BUNDLE_ROOT
    _verify_install_bundle || return
    UPGRADE_TARGET_VERSION="$INSTALL_VERSION"
    return 0
  fi

  local version
  if [[ "$mode" == reinstall ]]; then
    version="$current_version"
  else
    version="$(_resolve_release_version)" || return
  fi
  UPGRADE_FETCH_ROOT="$(mktemp -d /tmp/ezopenpn-upgrade.XXXXXX)" || return
  chmod 0700 "$UPGRADE_FETCH_ROOT"
  local base_url asset cosign_bin
  base_url="$(_release_base_url "$version")"
  for asset in \
    ezopenpn-bundle.tar.gz \
    SHA256SUMS \
    ezopenpn-bundle.sigstore.json; do
    _download_release_asset "$base_url" "$asset" \
      "${UPGRADE_FETCH_ROOT}/${asset}" || return
  done
  cosign_bin="$(_prepare_cosign "$UPGRADE_FETCH_ROOT")" || return
  verify_release_bundle "$UPGRADE_FETCH_ROOT" "$version" "$cosign_bin" || return
  UPGRADE_BUNDLE_ROOT="${UPGRADE_FETCH_ROOT}/bundle"
  mkdir -p "$UPGRADE_BUNDLE_ROOT"
  tar -xzf "${UPGRADE_FETCH_ROOT}/ezopenpn-bundle.tar.gz" \
    -C "$UPGRADE_BUNDLE_ROOT" || return
  EZOPENPN_BUNDLE_ROOT="$UPGRADE_BUNDLE_ROOT"
  export EZOPENPN_BUNDLE_ROOT
  _verify_install_bundle || return
  UPGRADE_TARGET_VERSION="$INSTALL_VERSION"
}

_upgrade_preflight() {
  if [[ "${TEST_UPGRADE_PREFLIGHT:-0}" == 1 ]]; then
    return 0
  fi
  local report observed_ip expected_ip
  report="$(run_preflight)" || {
    printf '%s\n' "$report" >&2
    return 1
  }
  observed_ip="$(python3 -c \
    'import json,sys; value=json.load(sys.stdin); assert value["ok"] and value["mode"] == "maintenance"; print(value["public_ipv4"])' \
    <<<"$report")" || return
  expected_ip="$(_upgrade_state_field public_ipv4)" || return
  [[ "$observed_ip" == "$expected_ip" ]]
}

_upgrade_create_preimage() {
  if [[ -n "${TEST_UPGRADE_BACKUP_BIN:-}" ]]; then
    UPGRADE_PREIMAGE="$("$TEST_UPGRADE_BACKUP_BIN" create)" || return
  else
    _backup_create_internal 1 || return
    UPGRADE_PREIMAGE="$BACKUP_CREATED_ARCHIVE"
  fi
  [[ -n "$UPGRADE_PREIMAGE" && "$UPGRADE_PREIMAGE" == /* ]]
}

_upgrade_restore_preimage() {
  if [[ -n "${TEST_UPGRADE_BACKUP_BIN:-}" ]]; then
    "$TEST_UPGRADE_BACKUP_BIN" restore "$UPGRADE_PREIMAGE"
  else
    _backup_restore_preimage \
      "$UPGRADE_PREIMAGE" "$(_backup_path /var/backups/ezopenpn)"
  fi
}

_upgrade_pull_images() {
  if [[ -n "${TEST_UPGRADE_PULL_BIN:-}" ]]; then
    "$TEST_UPGRADE_PULL_BIN"
    return
  fi
  local image
  for image in \
    "$INSTALL_CONTROL_IMAGE" \
    "$INSTALL_XRAY_IMAGE" \
    "$INSTALL_HYSTERIA_IMAGE" \
    "$INSTALL_GATEWAY_IMAGE" \
    "$INSTALL_CERT_SYNC_IMAGE"; do
    docker pull "$image" >/dev/null || return
  done
}

_upgrade_write_environment() {
  local destination="$1"
  python3 - \
    "$destination" "$INSTALL_PUBLIC_IP" "$INSTALL_CONTROL_IMAGE" \
    "$INSTALL_XRAY_IMAGE" "$INSTALL_HYSTERIA_IMAGE" "$INSTALL_GATEWAY_IMAGE" \
    "$INSTALL_CERT_SYNC_IMAGE" <<'PY'
import os
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
names = (
    "PUBLIC_IP",
    "CONTROL_IMAGE",
    "XRAY_IMAGE",
    "HYSTERIA_IMAGE",
    "GATEWAY_IMAGE",
    "CERT_SYNC_IMAGE",
)
values = sys.argv[2:]
if len(values) != len(names):
    raise SystemExit(1)
if re.fullmatch(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", values[0]) is None:
    raise SystemExit(1)
if any("\n" in value or "\r" in value for value in values):
    raise SystemExit(1)
descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
    for name, value in zip(names, values):
        stream.write(f"{name}={value}\n")
    stream.flush()
    os.fsync(stream.fileno())
PY
}

_upgrade_validate_candidate() {
  local stage="$1"
  docker compose \
    --env-file "$stage/stack.env" \
    -f "$stage/etc/compose.yaml" \
    --project-name ezopenpn config --quiet >/dev/null || return
  docker run --rm \
    --network none \
    --read-only \
    --user 0:0 \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --pids-limit 64 \
    --memory 128m \
    --mount "type=bind,src=${stage}/runtime/xray/config.json,dst=/etc/xray/config.json,readonly" \
    --entrypoint /usr/local/bin/xray \
    "$INSTALL_XRAY_IMAGE" run -test -config /etc/xray/config.json >/dev/null || return
  docker run --rm \
    --network none \
    --read-only \
    --user 0:0 \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --pids-limit 64 \
    --memory 128m \
    --env "PUBLIC_IP=${INSTALL_PUBLIC_IP}" \
    --mount "type=bind,src=${stage}/etc/Caddyfile,dst=/etc/caddy/Caddyfile,readonly" \
    --entrypoint caddy \
    "$INSTALL_GATEWAY_IMAGE" adapt --config /etc/caddy/Caddyfile >/dev/null
}

_upgrade_apply_laboratory_gateway() {
  local stage="$1"
  local laboratory
  laboratory="$(_upgrade_state_field laboratory_mode)" || return
  if [[ "$laboratory" == false ]]; then
    return 0
  fi
  [[ "$laboratory" == true ]] || return 1

  local source="${UPGRADE_BUNDLE_ROOT}/installer/lab/Caddyfile"
  local destination="${stage}/etc/Caddyfile"
  if [[ ! -f "$source" || -L "$source" || ! -f "$destination" || \
    -L "$destination" ]]; then
    return 1
  fi
  install -m 0640 "$source" "$destination"
}

_upgrade_prepare_candidate() {
  local stage="$1"
  if [[ -n "${TEST_UPGRADE_PREPARE_BIN:-}" ]]; then
    "$TEST_UPGRADE_PREPARE_BIN" "$UPGRADE_BUNDLE_ROOT" "$stage"
    return
  fi
  mkdir -p "$stage/etc" "$stage/runtime/xray" "$stage/runtime/hysteria"
  python3 "$UPGRADE_BUNDLE_ROOT/installer/render_config.py" \
    --values "$(_backup_path /var/lib/ezopenpn/runtime/material/runtime-values.json)" \
    --node "$(_backup_path /var/lib/ezopenpn/runtime/material/node.json)" \
    --public-ip "$INSTALL_PUBLIC_IP" \
    --deploy-root "$UPGRADE_BUNDLE_ROOT/deploy" \
    --etc-root "$stage/etc" \
    --runtime-root "$stage/runtime" || return
  _upgrade_apply_laboratory_gateway "$stage" || return
  _upgrade_write_environment "$stage/stack.env" || return
  _upgrade_validate_candidate "$stage"
}

_upgrade_install_file() {
  local source="$1"
  local destination="$2"
  local mode="$3"
  local owner="$4"
  if [[ ! -f "$source" || -L "$source" || -L "$destination" || \
    ( -e "$destination" && ! -f "$destination" ) ]]; then
    return 1
  fi
  local temporary="${destination}.upgrade-$$-${RANDOM}"
  install -m "$mode" "$source" "$temporary" || return
  if [[ -z "${EZOPENPN_ROOT_PREFIX:-}" ]]; then
    chown -- "$owner" "$temporary" || {
      unlink -- "$temporary" || true
      return 1
    }
  fi
  mv -f -- "$temporary" "$destination"
}

_upgrade_install_rendered() {
  local stage="$1"
  _upgrade_install_file \
    "$stage/etc/control.toml" "$(_backup_path /etc/ezopenpn/control.toml)" \
    0640 root:10001 || return
  _upgrade_install_file \
    "$stage/etc/Caddyfile" "$(_backup_path /etc/ezopenpn/Caddyfile)" \
    0640 root:11003 || return
  _upgrade_install_file \
    "$stage/etc/compose.yaml" "$(_backup_path /etc/ezopenpn/compose.yaml)" \
    0640 root:root || return
  _upgrade_install_file \
    "$stage/stack.env" "$(_backup_path /etc/ezopenpn/stack.env)" \
    0640 root:root || return
  _upgrade_install_file \
    "$stage/runtime/xray/config.json" \
    "$(_backup_path /var/lib/ezopenpn/runtime/xray/config.json)" \
    0600 10002:11001 || return
  _upgrade_install_file \
    "$stage/runtime/hysteria/config.yaml" \
    "$(_backup_path /var/lib/ezopenpn/runtime/hysteria/config.yaml)" \
    0600 10003:11003
}

_upgrade_save_host_tools() {
  local stage="$1"
  [[ -z "${EZOPENPN_ROOT_PREFIX:-}" ]] || return 0
  mkdir -p "$stage/host-tools"
  local unit=/etc/systemd/system/ezopenpn.service
  local cli=/usr/local/bin/ezopenpn
  if [[ -f "$unit" && ! -L "$unit" ]]; then
    cp -- "$unit" "$stage/host-tools/unit"
    : >"$stage/host-tools/unit.present"
  fi
  if [[ -f "$cli" && ! -L "$cli" ]]; then
    cp -- "$cli" "$stage/host-tools/cli"
    : >"$stage/host-tools/cli.present"
  fi
}

_upgrade_save_current_release() {
  local stage="$1"
  local source
  source="$(_backup_path "/etc/ezopenpn/${UPGRADE_OLD_CURRENT}")"
  python3 - "$source" "$stage/release-before" <<'PY'
import os
import shutil
import stat
import sys
from pathlib import Path

source = Path(sys.argv[1])
destination = Path(sys.argv[2])
status = source.lstat()
if stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
    raise SystemExit(1)
for root, directories, files in os.walk(source, followlinks=False):
    for name in [*directories, *files]:
        if (Path(root) / name).is_symlink():
            raise SystemExit(1)
shutil.copytree(source, destination)
PY
}

_upgrade_remove_target_release() {
  local releases_root target
  releases_root="$(_backup_path /etc/ezopenpn/releases)"
  target="${releases_root}/${UPGRADE_TARGET_VERSION}"
  python3 - "$releases_root" "$target" "$UPGRADE_TARGET_VERSION" <<'PY'
import re
import shutil
import stat
import sys
from pathlib import Path

parent = Path(sys.argv[1]).absolute()
target = Path(sys.argv[2]).absolute()
version = sys.argv[3]
if re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", version) is None:
    raise SystemExit(1)
if target.parent != parent or target.name != version:
    raise SystemExit(1)
try:
    status = target.lstat()
except FileNotFoundError:
    raise SystemExit(0)
if stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
    raise SystemExit(1)
shutil.rmtree(target)
PY
}

_upgrade_restore_current_release() {
  local stage="$1"
  local releases_root destination
  releases_root="$(_backup_path /etc/ezopenpn/releases)"
  destination="${releases_root}/${UPGRADE_CURRENT_VERSION}"
  python3 - \
    "$stage/release-before" "$releases_root" "$destination" \
    "$UPGRADE_CURRENT_VERSION" <<'PY'
import os
import re
import shutil
import stat
import sys
import tempfile
from pathlib import Path

source = Path(sys.argv[1])
parent = Path(sys.argv[2]).absolute()
destination = Path(sys.argv[3]).absolute()
version = sys.argv[4]
if re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", version) is None:
    raise SystemExit(1)
if destination.parent != parent or destination.name != version:
    raise SystemExit(1)
source_status = source.lstat()
if stat.S_ISLNK(source_status.st_mode) or not stat.S_ISDIR(source_status.st_mode):
    raise SystemExit(1)
temporary = Path(tempfile.mkdtemp(prefix=f".{version}.restore-", dir=parent))
temporary.rmdir()
try:
    shutil.copytree(source, temporary)
    if destination.exists():
        destination_status = destination.lstat()
        if stat.S_ISLNK(destination_status.st_mode) or not stat.S_ISDIR(
            destination_status.st_mode
        ):
            raise SystemExit(1)
        shutil.rmtree(destination)
    os.replace(temporary, destination)
finally:
    if temporary.exists():
        shutil.rmtree(temporary)
PY
}

_upgrade_install_host_tools() {
  [[ -z "${EZOPENPN_ROOT_PREFIX:-}" ]] || return 0
  install -m 0644 "$INSTALL_RELEASE_ROOT/installer/systemd/ezopenpn.service" \
    /etc/systemd/system/ezopenpn.service || return
  install -m 0755 "$INSTALL_RELEASE_ROOT/installer/bin/ezopenpn" \
    /usr/local/bin/ezopenpn || return
  systemctl daemon-reload
}

_upgrade_restore_host_tools() {
  local stage="$1"
  [[ -z "${EZOPENPN_ROOT_PREFIX:-}" ]] || return 0
  if [[ -f "$stage/host-tools/unit.present" ]]; then
    install -m 0644 "$stage/host-tools/unit" /etc/systemd/system/ezopenpn.service
  else
    unlink -- /etc/systemd/system/ezopenpn.service 2>/dev/null || true
  fi
  if [[ -f "$stage/host-tools/cli.present" ]]; then
    install -m 0755 "$stage/host-tools/cli" /usr/local/bin/ezopenpn
  else
    unlink -- /usr/local/bin/ezopenpn 2>/dev/null || true
  fi
  systemctl daemon-reload
}

_upgrade_service_command() {
  if [[ -n "${TEST_UPGRADE_SERVICE_BIN:-}" ]]; then
    "$TEST_UPGRADE_SERVICE_BIN" "$1"
  else
    _backup_service_command "$1"
  fi
}

_upgrade_migrate() {
  if [[ -n "${TEST_UPGRADE_MIGRATE_BIN:-}" ]]; then
    "$TEST_UPGRADE_MIGRATE_BIN"
    return
  fi
  _backup_compose run --rm --no-deps control python -m ezopenpn.cli \
    --config /etc/ezopenpn/control.toml migrate >/dev/null
}

_upgrade_switch_current() {
  local target="$1"
  local current
  current="$(_backup_path /etc/ezopenpn/current)"
  python3 - "$current" "$target" <<'PY'
import os
import re
import sys
from pathlib import Path

current = Path(sys.argv[1])
target = sys.argv[2]
if re.fullmatch(r"releases/v[0-9]+\.[0-9]+\.[0-9]+", target) is None:
    raise SystemExit(1)
temporary = current.with_name(current.name + f".upgrade-{os.getpid()}")
temporary.unlink(missing_ok=True)
os.symlink(target, temporary)
try:
    os.replace(temporary, current)
finally:
    temporary.unlink(missing_ok=True)
PY
}

_upgrade_write_state_version() {
  local version="$1"
  python3 - "$(_upgrade_state_path)" "$version" <<'PY'
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

path = Path(sys.argv[1])
version = sys.argv[2]
if re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", version) is None:
    raise SystemExit(1)
value = json.loads(path.read_text(encoding="utf-8"))
if not isinstance(value, dict) or not isinstance(value.get("version"), str):
    raise SystemExit(1)
value["version"] = version
value["updated_at"] = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
temporary = path.with_name(path.name + ".upgrade")
descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
finally:
    temporary.unlink(missing_ok=True)
PY
}

_upgrade_journal_path() {
  _backup_path /var/lib/ezopenpn/operations/upgrade-transaction.json
}

_upgrade_write_journal() {
  local phase="$1"
  UPGRADE_PHASE="$phase"
  python3 - \
    "$(_upgrade_journal_path)" "$phase" "$UPGRADE_CURRENT_VERSION" \
    "$UPGRADE_TARGET_VERSION" "$UPGRADE_OLD_CURRENT" "$UPGRADE_PREIMAGE" \
    "$UPGRADE_STAGE" <<'PY'
import json
import os
import sys
from pathlib import Path

path = Path(sys.argv[1])
value = {
    "current_version": sys.argv[3],
    "old_current": sys.argv[5],
    "phase": sys.argv[2],
    "preimage": sys.argv[6],
    "stage": sys.argv[7],
    "target_version": sys.argv[4],
}
temporary = path.with_name(path.name + ".tmp")
descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(value, stream, separators=(",", ":"), sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
finally:
    temporary.unlink(missing_ok=True)
PY
  write_operation_checkpoint upgrade "$phase"
}

_upgrade_clear_journal() {
  local journal
  journal="$(_upgrade_journal_path)"
  if [[ -f "$journal" && ! -L "$journal" ]]; then
    unlink -- "$journal"
  fi
  clear_operation_checkpoint
}

_upgrade_write_failure_record() {
  local failed_phase="$1"
  local backup_root destination
  backup_root="$(_backup_path /var/backups/ezopenpn)"
  destination="${backup_root}/failed-upgrade-$(date -u +%Y%m%dT%H%M%SZ)-$$.json"
  python3 - \
    "$destination" "$UPGRADE_CURRENT_VERSION" "$UPGRADE_TARGET_VERSION" \
    "$failed_phase" <<'PY'
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

path = Path(sys.argv[1])
value = {
    "current_version": sys.argv[2],
    "failed_phase": sys.argv[4],
    "recorded_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    "target_version": sys.argv[3],
}
descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
    json.dump(value, stream, separators=(",", ":"), sort_keys=True)
    stream.write("\n")
PY
}

_upgrade_rollback() {
  local failed_phase="$1"
  _upgrade_service_command stop || return 1
  _upgrade_restore_current_release "$UPGRADE_STAGE" || return 1
  _upgrade_switch_current "$UPGRADE_OLD_CURRENT" || return 1
  _upgrade_restore_host_tools "$UPGRADE_STAGE" || return 1
  _upgrade_write_state_version "$UPGRADE_CURRENT_VERSION" || return 1
  _upgrade_restore_preimage || return 1
  _upgrade_service_command start || return 1
  _upgrade_service_command health || return 1
  _upgrade_write_failure_record "$failed_phase" || true
  _upgrade_clear_journal
}

_upgrade_read_journal() {
  local journal
  journal="$(_upgrade_journal_path)"
  [[ -f "$journal" && ! -L "$journal" ]] || return 1
  local values
  values="$(python3 - "$journal" <<'PY'
import json
import re
import sys
from pathlib import Path

value = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
required = {
    "current_version",
    "old_current",
    "phase",
    "preimage",
    "stage",
    "target_version",
}
if not isinstance(value, dict) or set(value) != required:
    raise SystemExit(1)
if value["phase"] not in {"prepared", "switching", "switched", "migrated", "committing"}:
    raise SystemExit(1)
if re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", value["current_version"]) is None:
    raise SystemExit(1)
if re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", value["target_version"]) is None:
    raise SystemExit(1)
if re.fullmatch(r"releases/v[0-9]+\.[0-9]+\.[0-9]+", value["old_current"]) is None:
    raise SystemExit(1)
for key in ("phase", "preimage", "stage"):
    if not isinstance(value[key], str) or "\n" in value[key]:
        raise SystemExit(1)
print(value["current_version"])
print(value["target_version"])
print(value["old_current"])
print(value["preimage"])
print(value["stage"])
print(value["phase"])
PY
)" || return
  local fields=() field
  while IFS= read -r field; do
    fields+=("$field")
  done <<<"$values"
  [[ "${#fields[@]}" -eq 6 ]] || return 1
  UPGRADE_CURRENT_VERSION="${fields[0]}"
  UPGRADE_TARGET_VERSION="${fields[1]}"
  UPGRADE_OLD_CURRENT="${fields[2]}"
  UPGRADE_PREIMAGE="${fields[3]}"
  UPGRADE_STAGE="${fields[4]}"
  UPGRADE_PHASE="${fields[5]}"
  local operations_root
  operations_root="$(_backup_path /var/lib/ezopenpn/operations)"
  if [[ "$UPGRADE_PREIMAGE" != /* || ! -e "$UPGRADE_PREIMAGE" || \
    "$UPGRADE_STAGE" != "${operations_root}/.stage."* || \
    ! -d "$UPGRADE_STAGE" || -L "$UPGRADE_STAGE" ]]; then
    return 1
  fi
}

_upgrade_recover_interrupted() {
  local journal checkpoint
  journal="$(_upgrade_journal_path)"
  if [[ ! -e "$journal" && ! -L "$journal" ]]; then
    checkpoint="$(operation_checkpoint_path)"
    if [[ -e "$checkpoint" || -L "$checkpoint" ]]; then
      die 1 "E_UPGRADE_CHECKPOINT: обнаружена другая незавершённая операция"
      return
    fi
    return 0
  fi
  _upgrade_read_journal || {
    die 1 "E_UPGRADE_JOURNAL: журнал прерванной операции повреждён"
    return
  }
  if [[ "$UPGRADE_PHASE" == prepared ]]; then
    _upgrade_clear_journal
    _upgrade_cleanup_stage
    return 0
  fi
  if ! _upgrade_rollback interrupted; then
    die 1 "E_UPGRADE_RECOVERY: прерванную операцию не удалось откатить"
    return
  fi
  _upgrade_cleanup_stage
}

_upgrade_transaction() {
  local mode="$1"
  local comparison operations_root failure="" touched=0 stop_attempted=0
  _upgrade_preflight || {
    die 1 "E_UPGRADE_PREFLIGHT: сервер не прошёл проверку"
    return
  }
  UPGRADE_CURRENT_VERSION="$(_upgrade_state_field version)" || return 1
  UPGRADE_OLD_CURRENT="$(_upgrade_current_link)" || {
    die 1 "E_UPGRADE_CURRENT: текущий выпуск не определён"
    return
  }
  if [[ "$UPGRADE_OLD_CURRENT" != "releases/${UPGRADE_CURRENT_VERSION}" ]]; then
    die 1 "E_UPGRADE_CURRENT: состояние и current расходятся"
    return
  fi
  INSTALL_PUBLIC_IP="$(_upgrade_state_field public_ipv4)" || return 1
  _upgrade_fetch_verified_bundle "$mode" "$UPGRADE_CURRENT_VERSION" || {
    _upgrade_cleanup_fetch
    die 1 "E_UPGRADE_RELEASE: выпуск не удалось скачать или проверить"
    return
  }
  comparison="$(_upgrade_compare_versions \
    "$UPGRADE_TARGET_VERSION" "$UPGRADE_CURRENT_VERSION")" || {
    _upgrade_cleanup_fetch
    die 1 "E_UPGRADE_VERSION: версии выпуска не удалось сравнить"
    return
  }
  if [[ "$mode" == reinstall && "$comparison" != 0 ]]; then
    _upgrade_cleanup_fetch
    die 1 "E_REINSTALL_VERSION: переустановка требует текущий выпуск"
    return
  fi
  if [[ "$comparison" == -1 ]]; then
    _upgrade_cleanup_fetch
    die 1 "E_UPGRADE_DOWNGRADE: переход на более старый выпуск запрещён"
    return
  fi
  if [[ "$mode" == update && "$comparison" == 0 ]]; then
    _upgrade_cleanup_fetch
    printf '%s\n' 'Уже установлен последний стабильный выпуск.'
    return 0
  fi

  _upgrade_create_preimage || {
    _upgrade_cleanup_fetch
    die 1 "E_UPGRADE_BACKUP: резервная копия не создана"
    return
  }
  operations_root="$(_backup_path /var/lib/ezopenpn/operations)"
  UPGRADE_STAGE="$(mktemp -d "${operations_root}/.stage.XXXXXXXX")" || {
    _upgrade_cleanup_fetch
    die 1 "E_UPGRADE_STAGE: временный каталог не создан"
    return
  }
  chmod 0700 "$UPGRADE_STAGE"
  if ! _upgrade_pull_images; then
    failure=pull
  elif ! _upgrade_prepare_candidate "$UPGRADE_STAGE"; then
    failure=prepare
  elif ! _upgrade_save_host_tools "$UPGRADE_STAGE"; then
    failure="host-tools"
  elif ! _upgrade_save_current_release "$UPGRADE_STAGE"; then
    failure="current-release"
  elif ! _upgrade_write_journal prepared; then
    failure=journal
  fi
  if [[ -n "$failure" ]]; then
    _upgrade_write_failure_record "$failure" || true
    _upgrade_clear_journal
    _upgrade_cleanup_stage
    _upgrade_cleanup_fetch
    die 1 "E_UPGRADE_PREPARE: новый выпуск не подготовлен"
    return
  fi

  _upgrade_write_journal switching || failure=journal
  stop_attempted=1
  if [[ -z "$failure" ]] && ! _upgrade_service_command stop; then
    failure=stop
  fi
  if [[ -z "$failure" ]]; then
    touched=1
    INSTALL_VERSION="$UPGRADE_TARGET_VERSION"
    EZOPENPN_BUNDLE_ROOT="$UPGRADE_BUNDLE_ROOT"
    export EZOPENPN_BUNDLE_ROOT
    if ! _upgrade_remove_target_release; then
      failure="release-cleanup"
    elif ! _install_release_files; then
      failure=switch
    elif ! _upgrade_install_rendered "$UPGRADE_STAGE"; then
      failure=configuration
    elif ! _upgrade_install_host_tools; then
      failure="host-tools"
    elif ! _upgrade_write_journal switched; then
      failure=journal
    elif ! _upgrade_migrate; then
      failure=migrate
    elif ! _upgrade_write_journal migrated; then
      failure=journal
    elif ! _upgrade_service_command start; then
      failure=start
    elif ! _upgrade_service_command health; then
      failure=health
    elif ! _upgrade_write_journal committing; then
      failure=journal
    elif ! _upgrade_write_state_version "$UPGRADE_TARGET_VERSION"; then
      failure=state
    fi
  fi

  if [[ -n "$failure" ]]; then
    if (( touched == 1 )); then
      if ! _upgrade_rollback "$failure"; then
        _upgrade_cleanup_fetch
        release_operation_lock
        die 1 "E_UPGRADE_ROLLBACK: исходный выпуск не удалось вернуть"
        return
      fi
    elif (( stop_attempted == 1 )); then
      _upgrade_service_command start >/dev/null 2>&1 || true
      _upgrade_service_command health >/dev/null 2>&1 || true
      _upgrade_write_failure_record "$failure" || true
      _upgrade_clear_journal
    fi
    _upgrade_cleanup_stage
    _upgrade_cleanup_fetch
    die 1 "E_UPGRADE_HEALTH: новый выпуск отменён, исходный возвращён"
    return
  fi

  _upgrade_clear_journal
  _upgrade_cleanup_stage
  _upgrade_cleanup_fetch
  printf 'Готово. Установлен выпуск %s.\n' "$UPGRADE_TARGET_VERSION"
}

upgrade_run() {
  local mode="$1"
  _diagnostic_require_installation || return
  _backup_require_tool || return
  acquire_operation_lock "$mode" || return
  if ! _upgrade_recover_interrupted; then
    release_operation_lock
    return 1
  fi
  local status
  if _upgrade_transaction "$mode"; then
    status=0
  else
    status=$?
  fi
  release_operation_lock
  return "$status"
}
