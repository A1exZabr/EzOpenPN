#!/usr/bin/env bash

REMOVE_FINAL_ARCHIVE=""

_remove_path() {
  printf '%s%s\n' "${EZOPENPN_ROOT_PREFIX:-}" "$1"
}

_remove_require_clean_operation_state() {
  local checkpoint journal
  checkpoint="$(operation_checkpoint_path)"
  journal="$(_remove_path /var/lib/ezopenpn/operations/upgrade-transaction.json)"
  if [[ -e "$checkpoint" || -L "$checkpoint" || \
    -e "$journal" || -L "$journal" ]]; then
    die 1 "E_REMOVE_INTERRUPTED: сначала завершите восстановление через update или reinstall"
    return
  fi
}

_remove_service_command() {
  local action="$1"
  if [[ -n "${TEST_REMOVE_SERVICE_BIN:-}" ]]; then
    "$TEST_REMOVE_SERVICE_BIN" "$action"
    return
  fi
  case "$action" in
    disable) systemctl disable --now ezopenpn.service >/dev/null 2>&1 || true ;;
    down) _backup_compose down --remove-orphans >/dev/null ;;
    reload) systemctl daemon-reload ;;
    *) return 2 ;;
  esac
}

_remove_managed_services() {
  local status=0
  _remove_service_command disable || status=1
  _remove_service_command down || status=1
  rollback_firewall_rules || status=1
  return "$status"
}

_remove_reinstall_command() {
  printf '%s\n' \
    'curl -fsSL https://raw.githubusercontent.com/A1exZabr/EzOpenPN/main/installer/install.sh | sudo bash'
}

remove_uninstall() {
  _diagnostic_require_installation || return
  acquire_operation_lock uninstall || return
  if ! _remove_require_clean_operation_state; then
    release_operation_lock
    return 1
  fi
  local status
  if _remove_managed_services; then
    status=0
  else
    status=1
  fi
  release_operation_lock
  if (( status != 0 )); then
    die 1 "E_UNINSTALL_SERVICES: не все управляемые компоненты остановлены"
    return
  fi
  printf '%s\n' \
    'Управляемые сервисы остановлены, данные и резервные копии сохранены.' \
    'Для повторной установки выполните:'
  _remove_reinstall_command
}

_remove_snapshot_database() {
  local source="$1"
  local destination="$2"
  python3 - "$source" "$destination" <<'PY'
import os
import sqlite3
import stat
import sys
from pathlib import Path

source = Path(sys.argv[1]).absolute()
destination = Path(sys.argv[2]).absolute()
status = source.lstat()
if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
    raise SystemExit(1)
descriptor = os.open(
    destination,
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
    0o600,
)
os.close(descriptor)
try:
    with (
        sqlite3.connect(f"{source.as_uri()}?mode=ro", uri=True, timeout=5) as origin,
        sqlite3.connect(destination, timeout=5) as target,
    ):
        origin.execute("PRAGMA busy_timeout=5000")
        origin.backup(target, pages=128, sleep=0.01)
        quick = target.execute("PRAGMA quick_check").fetchall()
        foreign = target.execute("PRAGMA foreign_key_check").fetchone()
    if quick != [("ok",)] or foreign is not None:
        raise RuntimeError("snapshot verification failed")
    os.chmod(destination, 0o600)
except BaseException:
    destination.unlink(missing_ok=True)
    raise
PY
}

_remove_final_archive_path() {
  local timestamp
  timestamp="${TEST_REMOVE_TIMESTAMP:-$(date -u +%Y%m%dT%H%M%SZ)}"
  [[ "$timestamp" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || return 1
  printf '%s/var/backups/ezopenpn-final-%s.tar.gz\n' \
    "${EZOPENPN_ROOT_PREFIX:-}" "$timestamp"
}

_remove_create_final_archive() {
  local archive
  archive="$(_remove_final_archive_path)" || return
  if [[ -n "${TEST_REMOVE_FINAL_BACKUP_BIN:-}" ]]; then
    "$TEST_REMOVE_FINAL_BACKUP_BIN" "$archive" || return
    REMOVE_FINAL_ARCHIVE="$archive"
    return 0
  fi
  local backup_parent backup_root control_root snapshot stage verify_stage tool owner
  backup_parent="$(_remove_path /var/backups)"
  backup_root="$(_remove_path /var/backups/ezopenpn)"
  control_root="$(_remove_path /var/lib/ezopenpn/control)"
  tool="$(_backup_tool)"
  if [[ ! -d "$backup_parent" || -L "$backup_parent" || \
    ! -d "$backup_root" || -L "$backup_root" || \
    ! -d "$control_root" || -L "$control_root" || \
    -e "$archive" || -L "$archive" || \
    -e "${archive}.sha256" || -L "${archive}.sha256" ]]; then
    return 1
  fi
  snapshot="${control_root}/.final-snapshot-$$-${RANDOM}.sqlite3"
  _remove_snapshot_database \
    "${control_root}/ezopenpn.sqlite3" "$snapshot" || return
  stage="$(mktemp -d "${backup_root}/.stage.XXXXXXXX")" || {
    _backup_unlink_exact "$snapshot" || true
    return 1
  }
  chmod 0700 "$stage"
  if ! python3 "$tool" create \
    --root "$(_backup_host_root)" \
    --snapshot "$snapshot" \
    --staging "$stage" \
    --archive "$archive"; then
    _backup_cleanup_stage "$stage" "$backup_root"
    _backup_unlink_exact "$snapshot" || true
    _backup_unlink_exact "$archive" || true
    _backup_unlink_exact "${archive}.sha256" || true
    return 1
  fi
  _backup_cleanup_stage "$stage" "$backup_root"
  _backup_unlink_exact "$snapshot"
  verify_stage="$(mktemp -d "${backup_root}/.stage.XXXXXXXX")" || return 1
  chmod 0700 "$verify_stage"
  owner="${TEST_BACKUP_OWNER_UID:-0}"
  if ! python3 "$tool" validate \
    --archive "$archive" \
    --staging "$verify_stage" \
    --current-state "$(_remove_path /var/lib/ezopenpn/install.json)" \
    --expected-owner "$owner" >/dev/null; then
    _backup_cleanup_stage "$verify_stage" "$backup_root"
    return 1
  fi
  _backup_cleanup_stage "$verify_stage" "$backup_root"
  REMOVE_FINAL_ARCHIVE="$archive"
}

_remove_confirm_purge() {
  local input_path output_path product token
  input_path="${EZOPENPN_TTY_INPUT_PATH:-${EZOPENPN_TTY_PATH:-/dev/tty}}"
  output_path="${EZOPENPN_TTY_OUTPUT_PATH:-${EZOPENPN_TTY_PATH:-/dev/tty}}"
  if [[ ! -r "$input_path" || ! -w "$output_path" ]]; then
    die 2 "E_PURGE_TTY: интерактивный терминал недоступен"
    return
  fi
  exec 8<"$input_path"
  printf '%s' 'Для удаления всех данных введите EzOpenPN: ' >>"$output_path"
  if ! IFS= read -r -u 8 product; then
    exec 8<&-
    return 2
  fi
  printf '%s' 'Для окончательного подтверждения введите DELETE: ' >>"$output_path"
  if ! IFS= read -r -u 8 token; then
    exec 8<&-
    return 2
  fi
  exec 8<&-
  if [[ "$product" != EzOpenPN || "$token" != DELETE ]]; then
    die 2 "E_PURGE_CONFIRMATION: подтверждение не совпало, данные сохранены"
    return
  fi
}

_remove_tree_exact() {
  local target="$1"
  local expected="$2"
  require_absolute_safe_path "$target" || return
  [[ "$target" == "$expected" ]] || return 1
  python3 - "$target" "$expected" <<'PY'
import shutil
import stat
import sys
from pathlib import Path

target = Path(sys.argv[1]).absolute()
expected = Path(sys.argv[2]).absolute()
if target != expected:
    raise SystemExit(1)
status = target.lstat()
if stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
    raise SystemExit(1)
shutil.rmtree(target)
PY
}

_remove_file_exact() {
  local target="$1"
  local expected="$2"
  require_absolute_safe_path "$target" || return
  [[ "$target" == "$expected" ]] || return 1
  if [[ -d "$target" && ! -L "$target" ]]; then
    return 1
  fi
  if [[ -e "$target" || -L "$target" ]]; then
    unlink -- "$target"
  fi
}

remove_purge() {
  _diagnostic_require_installation || return
  _backup_require_tool || return
  acquire_operation_lock purge || return
  if ! _remove_require_clean_operation_state; then
    release_operation_lock
    return 1
  fi
  if ! _remove_create_final_archive; then
    release_operation_lock
    die 1 "E_PURGE_BACKUP: финальный архив не создан или не прошёл проверку"
    return
  fi
  if ! _remove_confirm_purge; then
    release_operation_lock
    return 2
  fi
  if ! _remove_managed_services; then
    release_operation_lock
    die 1 "E_PURGE_SERVICES: управляемые компоненты не остановлены"
    return
  fi
  local etc_root state_root backup_root cli unit status=0
  etc_root="$(_remove_path /etc/ezopenpn)"
  state_root="$(_remove_path /var/lib/ezopenpn)"
  backup_root="$(_remove_path /var/backups/ezopenpn)"
  cli="$(_remove_path /usr/local/bin/ezopenpn)"
  unit="$(_remove_path /etc/systemd/system/ezopenpn.service)"
  _remove_tree_exact "$etc_root" "$(_remove_path /etc/ezopenpn)" || status=1
  _remove_tree_exact "$state_root" "$(_remove_path /var/lib/ezopenpn)" || status=1
  _remove_tree_exact "$backup_root" "$(_remove_path /var/backups/ezopenpn)" || status=1
  _remove_file_exact "$cli" "$(_remove_path /usr/local/bin/ezopenpn)" || status=1
  _remove_file_exact "$unit" "$(_remove_path /etc/systemd/system/ezopenpn.service)" || status=1
  _remove_service_command reload >/dev/null 2>&1 || status=1
  release_operation_lock
  if (( status != 0 )); then
    die 1 "E_PURGE_REMOVE: удаление завершилось не полностью, финальный архив сохранён"
    return
  fi
  printf 'Данные удалены. Финальный архив сохранён: %s\n' "$REMOVE_FINAL_ARCHIVE"
}
