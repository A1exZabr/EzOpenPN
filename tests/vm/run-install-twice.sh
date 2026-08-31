#!/usr/bin/env bash

set -Eeuo pipefail

script_directory="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
assertion_script="${script_directory}/assert-preserved.sh"
host="${EZOPENPN_TEST_HOST:-}"
ssh_binary="${EZOPENPN_TEST_SSH_BIN:-ssh}"
install_command="${EZOPENPN_TEST_INSTALL_COMMAND:-curl -fsSL https://raw.githubusercontent.com/A1exZabr/EzOpenPN/main/installer/install.sh | sudo bash}"

if [[ -z "$host" || "$host" == -* || \
  ! "$host" =~ ^[A-Za-z0-9._@:-]+$ ]]; then
  printf '%s\n' 'E_VM_HOST: задайте безопасный SSH target через EZOPENPN_TEST_HOST' >&2
  exit 2
fi
if [[ ! -f "$assertion_script" || -L "$assertion_script" ]]; then
  printf '%s\n' 'E_VM_ASSERTION: сценарий проверки не найден' >&2
  exit 2
fi
if [[ "$ssh_binary" == */* && ! -x "$ssh_binary" ]]; then
  printf '%s\n' 'E_VM_SSH: SSH executable недоступен' >&2
  exit 2
fi

"$ssh_binary" -tt "$host" "$install_command"
"$ssh_binary" "$host" 'sudo bash -s -- capture' <"$assertion_script"
"$ssh_binary" -tt "$host" "$install_command"
"$ssh_binary" "$host" 'sudo bash -s -- verify' <"$assertion_script"

printf '%s\n' 'Повторная установка сохранила идентичность профилей и адрес панели.'
