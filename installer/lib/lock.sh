#!/usr/bin/env bash

EZOPENPN_LOCK_HELD=0
EZOPENPN_LOCK_BACKEND=""
EZOPENPN_LOCK_DIRECTORY=""

_operation_lock_busy() {
  die 73 "E_OPERATION_LOCKED: другая операция EzOpenPN ещё выполняется"
}

acquire_operation_lock() {
  local operation="${1:-}"
  if [[ -z "$operation" || "$operation" == *[!a-z0-9_-]* ]]; then
    die 64 "E_OPERATION_NAME: неверное имя операции"
    return
  fi
  if [[ "$EZOPENPN_LOCK_HELD" == "1" ]]; then
    die 73 "E_OPERATION_LOCKED: эта оболочка уже удерживает блокировку"
    return
  fi

  local run_root="${EZOPENPN_RUN_ROOT:-/run}"
  local lock_parent="${run_root}/lock"
  local lock_path="${lock_parent}/ezopenpn.lock"
  mkdir -p "$lock_parent"
  chmod 0755 "$lock_parent"

  if command -v flock >/dev/null 2>&1; then
    exec 9>"$lock_path"
    if ! flock -n 9; then
      exec 9>&-
      _operation_lock_busy
      return
    fi
    EZOPENPN_LOCK_BACKEND="flock"
  else
    EZOPENPN_LOCK_DIRECTORY="${lock_path}.directory"
    if ! mkdir "$EZOPENPN_LOCK_DIRECTORY" 2>/dev/null; then
      _operation_lock_busy
      return
    fi
    EZOPENPN_LOCK_BACKEND="directory"
  fi

  EZOPENPN_LOCK_HELD=1
  trap 'release_operation_lock' EXIT
  trap 'release_operation_lock; exit 129' HUP
  trap 'release_operation_lock; exit 130' INT
  trap 'release_operation_lock; exit 143' TERM
}

release_operation_lock() {
  if [[ "${EZOPENPN_LOCK_HELD:-0}" != "1" ]]; then
    return 0
  fi
  if [[ "$EZOPENPN_LOCK_BACKEND" == "flock" ]]; then
    flock -u 9 || true
    exec 9>&-
  elif [[ "$EZOPENPN_LOCK_BACKEND" == "directory" && \
    -n "$EZOPENPN_LOCK_DIRECTORY" ]]; then
    rmdir "$EZOPENPN_LOCK_DIRECTORY" 2>/dev/null || true
  fi
  EZOPENPN_LOCK_HELD=0
  EZOPENPN_LOCK_BACKEND=""
  EZOPENPN_LOCK_DIRECTORY=""
  trap - EXIT HUP INT TERM
}
