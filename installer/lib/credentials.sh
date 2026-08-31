#!/usr/bin/env bash

_credential_error() {
  unset ADMIN_LOGIN ADMIN_PASSWORD ADMIN_PASSWORD_CONFIRM
  die 64 "$1"
}

collect_admin_credentials() {
  set +x
  unset ADMIN_LOGIN ADMIN_PASSWORD ADMIN_PASSWORD_CONFIRM
  export -n ADMIN_LOGIN ADMIN_PASSWORD ADMIN_PASSWORD_CONFIRM 2>/dev/null || true

  local input_path="${EZOPENPN_TTY_INPUT_PATH:-${EZOPENPN_TTY_PATH:-/dev/tty}}"
  local output_path="${EZOPENPN_TTY_OUTPUT_PATH:-${EZOPENPN_TTY_PATH:-/dev/tty}}"
  if [[ ! -r "$input_path" || ! -w "$output_path" ]]; then
    _credential_error "E_CREDENTIAL_TTY: интерактивный терминал недоступен"
    return
  fi

  exec 8<"$input_path"
  printf '%s' 'Логин администратора: ' >>"$output_path"
  if ! IFS= read -r -u 8 ADMIN_LOGIN; then
    exec 8<&-
    _credential_error "E_CREDENTIAL_INPUT: логин не прочитан"
    return
  fi
  printf '%s' 'Пароль, не менее 12 символов: ' >>"$output_path"
  if ! IFS= read -r -s -u 8 ADMIN_PASSWORD; then
    exec 8<&-
    _credential_error "E_CREDENTIAL_INPUT: пароль не прочитан"
    return
  fi
  printf '\n%s' 'Повторите пароль: ' >>"$output_path"
  if ! IFS= read -r -s -u 8 ADMIN_PASSWORD_CONFIRM; then
    exec 8<&-
    _credential_error "E_CREDENTIAL_INPUT: подтверждение не прочитано"
    return
  fi
  printf '\n' >>"$output_path"
  exec 8<&-

  if (( ${#ADMIN_LOGIN} < 1 || ${#ADMIN_LOGIN} > 64 )); then
    _credential_error "E_CREDENTIAL_LOGIN: логин должен содержать от 1 до 64 символов"
    return
  fi
  if (( ${#ADMIN_PASSWORD} < 12 || ${#ADMIN_PASSWORD} > 1024 )); then
    _credential_error "E_CREDENTIAL_LENGTH: пароль должен содержать от 12 до 1024 символов"
    return
  fi
  if [[ "$ADMIN_PASSWORD" != "$ADMIN_PASSWORD_CONFIRM" ]]; then
    _credential_error "E_CREDENTIAL_CONFIRM: введённые пароли не совпадают"
    return
  fi
  unset ADMIN_PASSWORD_CONFIRM
  if [[ "$ADMIN_PASSWORD" == "$ADMIN_LOGIN" ]]; then
    _credential_error "E_CREDENTIAL_REUSE: логин и пароль должны различаться"
    return
  fi
}

initialize_admin_from_tty() {
  if [[ $# -lt 1 ]]; then
    die 64 "E_CREDENTIAL_COMMAND: команда управления не задана"
    return
  fi
  collect_admin_credentials || return

  local login="$ADMIN_LOGIN"
  local admin_value="$ADMIN_PASSWORD"
  unset ADMIN_LOGIN ADMIN_PASSWORD ADMIN_PASSWORD_CONFIRM
  local status
  if "$@" init-admin --login "$login" --password-stdin <<<"$admin_value"; then
    status=0
    # Used by the installation orchestrator after this helper returns.
    # shellcheck disable=SC2034
    INITIAL_ADMIN_LOGIN="$login"
  else
    status=$?
    unset INITIAL_ADMIN_LOGIN
  fi
  admin_value=''
  unset admin_value login ADMIN_LOGIN ADMIN_PASSWORD ADMIN_PASSWORD_CONFIRM
  return "$status"
}
