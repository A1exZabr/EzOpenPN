#!/usr/bin/env bash

set +x
set -Eeuo pipefail
umask 077

info() {
  printf '[EzOpenPN] %s\n' "$*"
}

warn() {
  printf '[EzOpenPN] WARNING: %s\n' "$*" >&2
}

die() {
  local status="${1:-1}"
  shift || true
  printf '[EzOpenPN] %s\n' "$*" >&2
  return "$status"
}

require_root() {
  local effective_uid="${EZOPENPN_TEST_EUID:-${EUID:-$(id -u)}}"
  if [[ "$effective_uid" != "0" ]]; then
    die 20 "E_PREFLIGHT_ROOT: запустите команду через sudo"
    return
  fi
}

require_tty() {
  local tty_path="${EZOPENPN_TTY_PATH:-/dev/tty}"
  if [[ ! -r "$tty_path" || ! -w "$tty_path" ]]; then
    die 21 "E_PREFLIGHT_TTY: нужен интерактивный терминал"
    return
  fi
}

require_absolute_safe_path() {
  local candidate="${1:-}"
  if [[ -z "$candidate" || "$candidate" != /* ]]; then
    die 64 "E_UNSAFE_PATH: требуется абсолютный путь"
    return
  fi
  case "$candidate" in
    *'$'* | *'{'* | *'}'* | *'*'* | *'?'* | *'['* | *']'*)
      die 64 "E_UNSAFE_PATH: путь содержит неразрешённые символы"
      return
      ;;
  esac

  local normalized
  normalized="$(python3 - "$candidate" <<'PY'
from __future__ import annotations

import os
import sys

print(os.path.normpath(sys.argv[1]))
PY
)"
  case "$normalized" in
    / | /root | /home | /Users | /home/* | /Users/*)
      if [[ "$normalized" =~ ^/home/[^/]+$ || "$normalized" =~ ^/Users/[^/]+$ ]]; then
        die 64 "E_UNSAFE_PATH: домашний каталог не может быть целью операции"
        return
      fi
      if [[ "$normalized" == "/" || "$normalized" == "/root" || \
        "$normalized" == "/home" || "$normalized" == "/Users" ]]; then
        die 64 "E_UNSAFE_PATH: слишком широкий путь"
        return
      fi
      ;;
  esac
  if [[ -n "${EZOPENPN_WORKSPACE_ROOT:-}" && \
    "$normalized" == "${EZOPENPN_WORKSPACE_ROOT%/}" ]]; then
    die 64 "E_UNSAFE_PATH: рабочий каталог не может быть целью операции"
    return
  fi
}
