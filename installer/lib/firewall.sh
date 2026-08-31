#!/usr/bin/env bash

_firewall_host_path() {
  printf '%s%s\n' "${EZOPENPN_ROOT_PREFIX:-}" "$1"
}

_firewall_state_path() {
  printf '%s/operations/firewall.rules\n' "${EZOPENPN_STATE_ROOT:-/var/lib/ezopenpn}"
}

_firewall_log_command() {
  local argument
  for argument in "$@"; do
    printf '%q ' "$argument" >>"$TEST_COMMAND_LOG"
  done
  printf '\n' >>"$TEST_COMMAND_LOG"
}

_firewall_command() {
  if [[ -n "${TEST_FIREWALL_BACKEND:-}" ]]; then
    _firewall_log_command "$@"
    return
  fi
  "$@"
}

_active_firewall_backend() {
  if [[ -n "${TEST_FIREWALL_BACKEND:-}" ]]; then
    printf '%s\n' "$TEST_FIREWALL_BACKEND"
    return
  fi
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    printf '%s\n' ufw
  elif command -v firewall-cmd >/dev/null 2>&1 && \
    firewall-cmd --state >/dev/null 2>&1; then
    printf '%s\n' firewalld
  else
    printf '%s\n' none
  fi
}

_record_firewall_rule() {
  local state_path
  state_path="$(_firewall_state_path)"
  mkdir -p "$(dirname "$state_path")"
  chmod 0700 "$(dirname "$state_path")"
  printf '%s\n' "$1" >>"$state_path"
  chmod 0600 "$state_path"
}

_ufw_status() {
  if [[ -n "${TEST_UFW_STATUS:-}" ]]; then
    printf '%s\n' "$TEST_UFW_STATUS"
  else
    ufw status
  fi
}

_install_firewalld_service() {
  local service_directory service_path temporary
  service_directory="$(_firewall_host_path /etc/firewalld/services)"
  service_path="${service_directory}/ezopenpn.xml"
  temporary="${service_path}.tmp"
  install -d -m 0755 "$service_directory"
  if [[ -e "$service_path" ]]; then
    grep -q '<short>EzOpenPN</short>' "$service_path" || {
      die 43 "E_FIREWALL_CONFLICT: service ezopenpn уже занят"
      return
    }
    return
  fi
  {
    printf '%s\n' '<?xml version="1.0" encoding="utf-8"?>'
    printf '%s\n' '<service>'
    printf '%s\n' '  <short>EzOpenPN</short>'
    printf '%s\n' '  <description>EzOpenPN managed ingress</description>'
    printf '%s\n' '  <port protocol="tcp" port="80"/>'
    printf '%s\n' '  <port protocol="tcp" port="443"/>'
    printf '%s\n' '  <port protocol="udp" port="443"/>'
    printf '%s\n' '  <port protocol="tcp" port="9443"/>'
    printf '%s\n' '</service>'
  } >"$temporary"
  chmod 0644 "$temporary"
  mv -f -- "$temporary" "$service_path"
}

apply_firewall_rules() {
  local state_path
  state_path="$(_firewall_state_path)"
  if [[ -s "$state_path" ]]; then
    return 0
  fi
  local backend
  backend="$(_active_firewall_backend)"
  case "$backend" in
    none)
      info "Host firewall не активен, его политика не изменена."
      ;;
    ufw)
      local rule
      for rule in 80/tcp 443/tcp 443/udp 9443/tcp; do
        if _ufw_status | grep -F "$rule" | grep -Fq EzOpenPN; then
          continue
        fi
        _firewall_command ufw allow "$rule" comment EzOpenPN
        _record_firewall_rule "ufw|${rule}"
      done
      ;;
    firewalld)
      _install_firewalld_service
      _record_firewall_rule "firewalld|service"
      _firewall_command firewall-cmd --reload
      _firewall_command firewall-cmd --permanent --add-service=ezopenpn
      _firewall_command firewall-cmd --add-service=ezopenpn
      ;;
    *)
      die 43 "E_FIREWALL_BACKEND: неподдерживаемый firewall"
      return
      ;;
  esac
}

rollback_firewall_rules() {
  local state_path
  state_path="$(_firewall_state_path)"
  [[ -f "$state_path" ]] || return 0
  local backend value
  while IFS='|' read -r backend value; do
    case "$backend" in
      ufw)
        _firewall_command ufw --force delete allow "$value" comment EzOpenPN || true
        ;;
      firewalld)
        _firewall_command firewall-cmd --remove-service=ezopenpn || true
        _firewall_command firewall-cmd --permanent --remove-service=ezopenpn || true
        local service_path
        service_path="$(_firewall_host_path /etc/firewalld/services/ezopenpn.xml)"
        if [[ -f "$service_path" ]] && grep -q '<short>EzOpenPN</short>' "$service_path"; then
          rm -f -- "$service_path"
        fi
        _firewall_command firewall-cmd --reload || true
        ;;
    esac
  done <"$state_path"
  rm -f -- "$state_path"
}
