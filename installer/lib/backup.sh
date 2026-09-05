#!/usr/bin/env bash

BACKUP_CREATED_ARCHIVE=""

_backup_path() {
  printf '%s%s\n' "${EZOPENPN_ROOT_PREFIX:-}" "$1"
}

_backup_host_root() {
  if [[ -n "${EZOPENPN_ROOT_PREFIX:-}" ]]; then
    printf '%s\n' "$EZOPENPN_ROOT_PREFIX"
  else
    printf '%s\n' /
  fi
}

_backup_tool() {
  local installer_root
  installer_root="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
  printf '%s\n' "${installer_root}/backup_archive.py"
}

_backup_require_tool() {
  local tool
  tool="$(_backup_tool)"
  if [[ ! -f "$tool" || -L "$tool" ]]; then
    die 3 "E_BACKUP_TOOL: модуль резервного копирования не найден"
    return
  fi
}

_backup_compose() {
  docker compose \
    --env-file "$(_backup_path /etc/ezopenpn/stack.env)" \
    -f "$(_backup_path /etc/ezopenpn/compose.yaml)" \
    --project-name ezopenpn "$@"
}

_backup_control_command() {
  if [[ -n "${TEST_BACKUP_CONTROL_BIN:-}" ]]; then
    "$TEST_BACKUP_CONTROL_BIN" "$@"
    return
  fi
  local invocation=(exec -T)
  if [[ "${BACKUP_CONTROL_OFFLINE:-0}" == 1 ]]; then
    invocation=(run --rm --no-deps -T)
  fi
  _backup_compose "${invocation[@]}" control python -m ezopenpn.cli \
    --config /etc/ezopenpn/control.toml "$@"
}

_backup_service_command() {
  local action="$1"
  if [[ -n "${TEST_BACKUP_SERVICE_BIN:-}" ]]; then
    "$TEST_BACKUP_SERVICE_BIN" "$action"
    return
  fi
  case "$action" in
    stop) systemctl stop ezopenpn.service ;;
    start) systemctl start ezopenpn.service ;;
    health)
      local service ready
      for _ in {1..60}; do
        ready=1
        for service in control xray hysteria gateway cert-sync; do
          if [[ "$(_diagnostic_service_health "$service")" != healthy ]]; then
            ready=0
            break
          fi
        done
        if [[ "$ready" == 1 ]] && _diagnostic_public_ready >/dev/null 2>&1; then
          return 0
        fi
        sleep 2
      done
      return 1
      ;;
    *) return 2 ;;
  esac
}

_backup_cleanup_stage() {
  local stage="$1"
  local backup_root="$2"
  [[ -n "$stage" && -d "$stage" && ! -L "$stage" ]] || return 0
  python3 "$(_backup_tool)" cleanup --path "$stage" --parent "$backup_root" \
    >/dev/null 2>&1 || true
}

_backup_unlink_exact() {
  local path="$1"
  [[ -n "$path" && -f "$path" && ! -L "$path" ]] || return 0
  unlink -- "$path"
}

_backup_archive_name() {
  local backup_root="$1"
  local timestamp candidate
  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  for _ in {1..100}; do
    candidate="${backup_root}/ezopenpn-${timestamp}-$$-${RANDOM}.tar.gz"
    if [[ ! -e "$candidate" && ! -L "$candidate" && \
      ! -e "${candidate}.sha256" && ! -L "${candidate}.sha256" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

_backup_create_internal() {
  local quiet="${1:-0}"
  local backup_root control_root snapshot_name snapshot_host snapshot_container
  local stage archive tool
  backup_root="$(_backup_path /var/backups/ezopenpn)"
  control_root="$(_backup_path /var/lib/ezopenpn/control)"
  tool="$(_backup_tool)"
  if [[ ! -d "$backup_root" || -L "$backup_root" || \
    ! -d "$control_root" || -L "$control_root" ]]; then
    die 3 "E_BACKUP_LAYOUT: каталоги установки недоступны"
    return
  fi
  chmod 0700 "$backup_root"
  snapshot_name=".backup-snapshot-$$-${RANDOM}-${RANDOM}.sqlite3"
  snapshot_host="${control_root}/${snapshot_name}"
  snapshot_container="/var/lib/ezopenpn/${snapshot_name}"
  if [[ -e "$snapshot_host" || -L "$snapshot_host" ]]; then
    die 1 "E_BACKUP_SNAPSHOT: временный путь уже занят"
    return
  fi
  if ! _backup_control_command backup-database --output "$snapshot_container" \
    >/dev/null; then
    _backup_unlink_exact "$snapshot_host" || true
    die 1 "E_BACKUP_DATABASE: снимок хранилища не создан"
    return
  fi
  if ! _backup_control_command verify-database --path "$snapshot_container" \
    >/dev/null; then
    _backup_unlink_exact "$snapshot_host" || true
    die 1 "E_BACKUP_DATABASE: снимок хранилища не прошёл проверку"
    return
  fi
  stage="$(mktemp -d "${backup_root}/.stage.XXXXXXXX")" || {
    _backup_unlink_exact "$snapshot_host" || true
    die 1 "E_BACKUP_STAGE: временный каталог не создан"
    return
  }
  chmod 0700 "$stage"
  if ! archive="$(_backup_archive_name "$backup_root")"; then
    _backup_cleanup_stage "$stage" "$backup_root"
    _backup_unlink_exact "$snapshot_host" || true
    die 1 "E_BACKUP_NAME: имя архива не создано"
    return
  fi
  if ! python3 "$tool" create \
    --root "$(_backup_host_root)" \
    --snapshot "$snapshot_host" \
    --staging "$stage" \
    --archive "$archive"; then
    _backup_cleanup_stage "$stage" "$backup_root"
    _backup_unlink_exact "$snapshot_host" || true
    _backup_unlink_exact "$archive" || true
    _backup_unlink_exact "${archive}.sha256" || true
    die 1 "E_BACKUP_ARCHIVE: архив не создан"
    return
  fi
  _backup_cleanup_stage "$stage" "$backup_root"
  _backup_unlink_exact "$snapshot_host"
  BACKUP_CREATED_ARCHIVE="$archive"
  if [[ "$quiet" != 1 ]]; then
    printf 'Резервная копия готова: %s\n' "$archive"
  fi
}

backup_create() {
  _diagnostic_require_installation || return
  _backup_require_tool || return
  acquire_operation_lock backup || return
  local status
  if _backup_create_internal 0; then
    status=0
  else
    status=$?
  fi
  release_operation_lock
  return "$status"
}

_backup_expected_owner() {
  printf '%s\n' "${TEST_BACKUP_OWNER_UID:-0}"
}

_backup_prepare_control_verification() {
  local database="$1"
  local control_root name host_path container_path
  control_root="$(_backup_path /var/lib/ezopenpn/control)"
  name=".restore-verify-$$-${RANDOM}.sqlite3"
  host_path="${control_root}/${name}"
  container_path="/var/lib/ezopenpn/${name}"
  install -m 0600 "$database" "$host_path"
  if [[ -z "${EZOPENPN_ROOT_PREFIX:-}" ]]; then
    chown -- 10001:10001 "$host_path"
  fi
  if _backup_control_command verify-database --path "$container_path" >/dev/null; then
    _backup_unlink_exact "$host_path"
    return 0
  fi
  _backup_unlink_exact "$host_path" || true
  return 1
}

_backup_extract_archive() {
  local archive="$1"
  local stage="$2"
  python3 "$(_backup_tool)" validate \
    --archive "$archive" \
    --staging "$stage" \
    --current-state "$(_backup_path /var/lib/ezopenpn/install.json)" \
    --expected-owner "$(_backup_expected_owner)" >/dev/null
}

_backup_apply_stage() {
  local stage="$1"
  python3 "$(_backup_tool)" apply \
    --root "$(_backup_host_root)" \
    --staging "$stage"
}

_backup_restore_preimage() {
  local archive="$1"
  local backup_root="$2"
  local stage
  stage="$(mktemp -d "${backup_root}/.stage.XXXXXXXX")" || return 1
  chmod 0700 "$stage"
  if ! _backup_extract_archive "$archive" "$stage" || \
    ! _backup_apply_stage "$stage"; then
    _backup_cleanup_stage "$stage" "$backup_root"
    return 1
  fi
  _backup_cleanup_stage "$stage" "$backup_root"
}

backup_restore() {
  local archive="${1:-}"
  _diagnostic_require_installation || return
  _backup_require_tool || return
  require_absolute_safe_path "$archive" || return 2
  acquire_operation_lock restore || return
  local backup_root stage preimage status=0 payload_touched=0 stop_attempted=0
  backup_root="$(_backup_path /var/backups/ezopenpn)"
  if [[ ! -d "$backup_root" || -L "$backup_root" ]]; then
    release_operation_lock
    die 3 "E_BACKUP_LAYOUT: каталог резервных копий недоступен"
    return
  fi
  stage="$(mktemp -d "${backup_root}/.stage.XXXXXXXX")" || {
    release_operation_lock
    die 1 "E_RESTORE_STAGE: временный каталог не создан"
    return
  }
  chmod 0700 "$stage"
  if ! _backup_extract_archive "$archive" "$stage" || \
    ! _backup_prepare_control_verification \
      "$stage/payload/database/ezopenpn.sqlite3"; then
    _backup_cleanup_stage "$stage" "$backup_root"
    release_operation_lock
    die 1 "E_RESTORE_VERIFY: архив отклонён до остановки сервисов"
    return
  fi
  if ! _backup_create_internal 1; then
    _backup_cleanup_stage "$stage" "$backup_root"
    release_operation_lock
    die 1 "E_RESTORE_PREIMAGE: текущие данные не сохранены"
    return
  fi
  preimage="$BACKUP_CREATED_ARCHIVE"
  stop_attempted=1
  if ! _backup_service_command stop; then
    status=1
  else
    payload_touched=1
    if ! _backup_apply_stage "$stage"; then
      status=1
    elif ! _backup_service_command start; then
      status=1
    elif ! _backup_service_command health; then
      status=1
    fi
  fi
  _backup_cleanup_stage "$stage" "$backup_root"
  if (( status != 0 )); then
    if (( payload_touched == 1 )); then
      if ! _backup_service_command stop || \
        ! _backup_restore_preimage "$preimage" "$backup_root" || \
        ! _backup_service_command start || \
        ! _backup_service_command health; then
        release_operation_lock
        die 1 "E_RESTORE_ROLLBACK: исходное состояние не удалось запустить"
        return
      fi
    elif (( stop_attempted == 1 )) && \
      { ! _backup_service_command start || ! _backup_service_command health; }; then
      release_operation_lock
      die 1 "E_RESTORE_ROLLBACK: исходное состояние не удалось запустить"
      return
    fi
    release_operation_lock
    die 1 "E_RESTORE_HEALTH: восстановление отменено, исходное состояние возвращено"
    return
  fi
  release_operation_lock
  printf '%s\n' 'Данные восстановлены и прошли проверку.'
}
