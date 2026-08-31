#!/usr/bin/env bash

_docker_host_path() {
  printf '%s%s\n' "${EZOPENPN_ROOT_PREFIX:-}" "$1"
}

_docker_log_command() {
  local argument
  for argument in "$@"; do
    printf '%q ' "$argument" >>"$TEST_COMMAND_LOG"
  done
  printf '\n' >>"$TEST_COMMAND_LOG"
}

_docker_host_command() {
  if [[ "${TEST_DOCKER_INSTALL:-}" == "1" ]]; then
    _docker_log_command "$@"
    return
  fi
  "$@"
}

_docker_is_ready() {
  if [[ -n "${TEST_DOCKER_READY:-}" ]]; then
    [[ "$TEST_DOCKER_READY" == "1" ]]
    return
  fi
  command -v docker >/dev/null 2>&1 || return 1
  docker info >/dev/null 2>&1 || return 1
  docker compose version >/dev/null 2>&1
}

_docker_os_value() {
  local name="$1"
  local test_name="TEST_OS_${name}"
  if [[ -n "${!test_name:-}" ]]; then
    printf '%s\n' "${!test_name}"
    return
  fi
  local release_key="$name"
  if [[ "$name" == "CODENAME" ]]; then
    release_key="VERSION_CODENAME"
  fi
  awk -F= -v key="$release_key" '
    $1 == key {
      value = substr($0, index($0, "=") + 1)
      gsub(/^"|"$/, "", value)
      print value
      exit
    }
  ' /etc/os-release
}

_record_docker_resources() {
  local resources_path="${EZOPENPN_STATE_ROOT:-/var/lib/ezopenpn}/operations/docker.resources"
  mkdir -p "$(dirname "$resources_path")"
  chmod 0700 "$(dirname "$resources_path")"
  printf '%s\n' "$@" >"$resources_path"
  chmod 0600 "$resources_path"
}

ensure_docker_engine() {
  if _docker_is_ready; then
    info "Совместимые Docker Engine и Compose уже установлены."
    return
  fi

  local os_id codename
  os_id="$(_docker_os_value ID)"
  codename="$(_docker_os_value CODENAME)"
  case "$os_id" in
    ubuntu | debian) ;;
    *)
      die 40 "E_DOCKER_OS: неподдерживаемый дистрибутив"
      return
      ;;
  esac
  if [[ -z "$codename" || "$codename" == *[!a-z0-9]* ]]; then
    die 40 "E_DOCKER_OS: не удалось определить codename"
    return
  fi

  local keyring_directory key_path source_directory source_path source_temporary
  keyring_directory="$(_docker_host_path /etc/apt/keyrings)"
  key_path="${keyring_directory}/docker.asc"
  source_directory="$(_docker_host_path /etc/apt/sources.list.d)"
  source_path="${source_directory}/docker.sources"
  source_temporary="${source_path}.tmp"

  _docker_host_command apt-get update
  _docker_host_command apt-get install -y --no-install-recommends ca-certificates curl gnupg
  install -d -m 0755 "$keyring_directory" "$source_directory"
  if [[ "${TEST_DOCKER_INSTALL:-}" == "1" ]]; then
    printf '%s\n' "test Docker signing key" >"$key_path"
  else
    curl --proto '=https' --tlsv1.2 -fsSL --connect-timeout 10 --max-time 60 \
      "https://download.docker.com/linux/${os_id}/gpg" -o "$key_path"
    local fingerprint
    fingerprint="$(gpg --batch --show-keys --with-colons "$key_path" 2>/dev/null | \
      awk -F: '$1 == "fpr" {print $10; exit}')"
    if [[ "$fingerprint" != "9DC858229FC7DD38854AE2D88D81803C0EBFCD88" ]]; then
      rm -f -- "$key_path"
      die 41 "E_DOCKER_KEY: подпись официального репозитория не совпала"
      return
    fi
  fi
  chmod 0644 "$key_path"

  {
    printf '%s\n' "Types: deb"
    printf 'URIs: https://download.docker.com/linux/%s\n' "$os_id"
    printf 'Suites: %s\n' "$codename"
    printf '%s\n' "Components: stable"
    printf '%s\n' "Architectures: amd64"
    printf 'Signed-By: %s\n' "$key_path"
  } >"$source_temporary"
  chmod 0644 "$source_temporary"
  mv -f -- "$source_temporary" "$source_path"
  sync -f "$source_directory" 2>/dev/null || true

  local conflicting_packages=(
    docker.io docker-compose docker-compose-v2 docker-doc docker-buildx
    podman-docker containerd runc
  )
  if [[ "${TEST_DOCKER_INSTALL:-}" == "1" ]]; then
    _docker_host_command apt-get remove -y "${conflicting_packages[@]}"
  else
    local installed_conflicts=()
    local package
    for package in "${conflicting_packages[@]}"; do
      if dpkg-query -W -f='${db:Status-Status}' "$package" 2>/dev/null | \
        grep -qx 'installed'; then
        installed_conflicts+=("$package")
      fi
    done
    if [[ ${#installed_conflicts[@]} -gt 0 ]]; then
      apt-get remove -y "${installed_conflicts[@]}"
    fi
  fi
  _docker_host_command apt-get update
  _docker_host_command apt-get install -y --no-install-recommends \
    docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  _docker_host_command systemctl enable --now docker
  _record_docker_resources "$key_path" "$source_path" \
    docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

  if [[ "${TEST_DOCKER_INSTALL:-}" == "1" ]]; then
    TEST_DOCKER_READY=1
  fi
  if ! _docker_is_ready; then
    die 42 "E_DOCKER_HEALTH: Docker Engine не отвечает"
    return
  fi
  info "Docker Engine и Compose готовы."
}
