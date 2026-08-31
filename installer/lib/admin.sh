#!/usr/bin/env bash

_admin_path() {
  printf '%s%s\n' "${EZOPENPN_ROOT_PREFIX:-}" "$1"
}

_admin_require_installation() {
  local state
  state="$(_admin_path /var/lib/ezopenpn/install.json)"
  if [[ ! -f "$state" || -L "$state" ]]; then
    die 3 "E_INSTALL_UNAVAILABLE: установка EzOpenPN не найдена"
    return
  fi
}

_admin_collect_password() {
  set +x
  unset ADMIN_RESET_VALUE ADMIN_RESET_CONFIRM
  export -n ADMIN_RESET_VALUE ADMIN_RESET_CONFIRM 2>/dev/null || true
  local input_path="${EZOPENPN_TTY_INPUT_PATH:-${EZOPENPN_TTY_PATH:-/dev/tty}}"
  local output_path="${EZOPENPN_TTY_OUTPUT_PATH:-${EZOPENPN_TTY_PATH:-/dev/tty}}"
  if [[ ! -r "$input_path" || ! -w "$output_path" ]]; then
    die 2 "E_CREDENTIAL_TTY: интерактивный терминал недоступен"
    return
  fi
  exec 8<"$input_path"
  printf '%s' 'Новый пароль, не менее 12 символов: ' >>"$output_path"
  if ! IFS= read -r -s -u 8 ADMIN_RESET_VALUE; then
    exec 8<&-
    die 2 "E_CREDENTIAL_INPUT: пароль не прочитан"
    return
  fi
  printf '\n%s' 'Повторите новый пароль: ' >>"$output_path"
  if ! IFS= read -r -s -u 8 ADMIN_RESET_CONFIRM; then
    exec 8<&-
    unset ADMIN_RESET_VALUE
    die 2 "E_CREDENTIAL_INPUT: подтверждение не прочитано"
    return
  fi
  printf '\n' >>"$output_path"
  exec 8<&-
  if (( ${#ADMIN_RESET_VALUE} < 12 || ${#ADMIN_RESET_VALUE} > 1024 )); then
    unset ADMIN_RESET_VALUE ADMIN_RESET_CONFIRM
    die 2 "E_CREDENTIAL_LENGTH: пароль должен содержать от 12 до 1024 символов"
    return
  fi
  if [[ "$ADMIN_RESET_VALUE" != "$ADMIN_RESET_CONFIRM" ]]; then
    unset ADMIN_RESET_VALUE ADMIN_RESET_CONFIRM
    die 2 "E_CREDENTIAL_CONFIRM: введённые пароли не совпадают"
    return
  fi
  unset ADMIN_RESET_CONFIRM
}

_admin_compose() {
  docker compose \
    --env-file "$(_admin_path /etc/ezopenpn/stack.env)" \
    -f "$(_admin_path /etc/ezopenpn/compose.yaml)" \
    --project-name ezopenpn "$@"
}

_admin_control_command() {
  if [[ -n "${TEST_ADMIN_CONTROL_BIN:-}" ]]; then
    "$TEST_ADMIN_CONTROL_BIN" "$@"
    return
  fi
  _admin_compose exec -T control python -m ezopenpn.cli \
    --config /etc/ezopenpn/control.toml "$@"
}

reset_admin_password() {
  _admin_require_installation || return
  acquire_operation_lock admin-reset || return
  if ! _admin_collect_password; then
    release_operation_lock
    return 2
  fi
  local reset_value="$ADMIN_RESET_VALUE"
  unset ADMIN_RESET_VALUE ADMIN_RESET_CONFIRM
  local status
  if _admin_control_command reset-password --password-stdin <<<"$reset_value"; then
    status=0
  else
    status=$?
  fi
  reset_value=''
  unset reset_value ADMIN_RESET_VALUE ADMIN_RESET_CONFIRM
  release_operation_lock
  if (( status != 0 )); then
    die 1 "E_ADMIN_RESET: пароль не удалось обновить"
    return
  fi
  printf '%s\n' 'Пароль обновлён. Все активные сеансы завершены. Профили сохранены.'
}
