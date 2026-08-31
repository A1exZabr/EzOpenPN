#!/usr/bin/env bash

_preflight_report() {
  local ok="$1"
  local mode="$2"
  local public_ip="$3"
  local diagnostic="$4"
  local detail="$5"
  python3 - "$ok" "$mode" "$public_ip" "$diagnostic" "$detail" <<'PY'
from __future__ import annotations

import json
import sys

report = {
    "detail": sys.argv[5],
    "diagnostic": sys.argv[4],
    "mode": sys.argv[2],
    "ok": sys.argv[1] == "true",
    "public_ipv4": sys.argv[3],
}
print(json.dumps(report, ensure_ascii=False, separators=(",", ":"), sort_keys=True))
PY
}

_preflight_fail() {
  local status="$1"
  local mode="$2"
  local public_ip="$3"
  local diagnostic="$4"
  local detail="$5"
  _preflight_report false "$mode" "$public_ip" "$diagnostic" "$detail"
  return "$status"
}

_os_release_value() {
  local path="$1"
  local name="$2"
  awk -F= -v key="$name" '
    $1 == key {
      value = substr($0, index($0, "=") + 1)
      gsub(/^"|"$/, "", value)
      print value
      exit
    }
  ' "$path"
}

_supported_operating_system() {
  local path="$1"
  [[ -r "$path" ]] || return 1
  local identifier version
  identifier="$(_os_release_value "$path" ID)"
  version="$(_os_release_value "$path" VERSION_ID)"
  case "${identifier}:${version}" in
    ubuntu:22.04 | ubuntu:24.04 | debian:12 | debian:13) return 0 ;;
    *) return 1 ;;
  esac
}

_public_ip_observation() {
  local test_name="$1"
  local url="$2"
  local test_value="${!test_name:-}"
  if [[ -n "$test_value" ]]; then
    printf '%s\n' "$test_value"
    return
  fi
  curl --proto '=https' --tlsv1.2 -fsSL --connect-timeout 5 --max-time 15 "$url"
}

detect_public_ipv4() {
  local first second address_output test_mode="false"
  first="$(_public_ip_observation TEST_PUBLIC_IP_A https://checkip.amazonaws.com)" || return 1
  second="$(_public_ip_observation TEST_PUBLIC_IP_B https://api.ipify.org)" || return 1
  if [[ -n "${TEST_IP_ADDR_OUTPUT:-}" ]]; then
    address_output="$TEST_IP_ADDR_OUTPUT"
    test_mode="true"
  else
    address_output="$(ip -4 -o addr show scope global)" || return 1
  fi
  python3 - "$first" "$second" "$address_output" "$test_mode" <<'PY'
from __future__ import annotations

import ipaddress
import re
import sys

try:
    first = ipaddress.ip_address(sys.argv[1].strip())
    second = ipaddress.ip_address(sys.argv[2].strip())
except ValueError as error:
    raise SystemExit(1) from error
if first.version != 4 or first != second:
    raise SystemExit(1)
if sys.argv[4] != "true" and not first.is_global:
    raise SystemExit(1)
assigned = {
    ipaddress.ip_interface(match).ip
    for match in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b", sys.argv[3])
}
if first not in assigned:
    raise SystemExit(1)
print(first)
PY
}

_listener_conflicts() {
  local listeners="$1"
  python3 - "$listeners" <<'PY'
from __future__ import annotations

import re
import sys

required = {(80, "tcp"), (443, "tcp"), (443, "udp"), (9443, "tcp")}
conflicts: set[tuple[int, str, str]] = set()
for line in sys.argv[1].splitlines():
    columns = line.split()
    if len(columns) < 4:
        continue
    protocol = "tcp" if columns[0] == "LISTEN" else "udp" if columns[0] == "UNCONN" else ""
    match = re.search(r":(\d+)$", columns[3])
    if not protocol or match is None:
        continue
    port = int(match.group(1))
    if (port, protocol) not in required:
        continue
    process = re.search(r'users:\(\("([^"\\]+)', line)
    owner = process.group(1) if process else "unknown"
    owner = re.sub(r"[^A-Za-z0-9_.-]", "", owner)[:64] or "unknown"
    conflicts.add((port, protocol, owner))
for port, protocol, owner in sorted(conflicts):
    print(f"{port}/{protocol} {owner}")
PY
}

_socket_listing() {
  if [[ -n "${TEST_SS_OUTPUT+x}" ]]; then
    printf '%s\n' "$TEST_SS_OUTPUT"
  else
    ss -H -lntup
  fi
}

_foreign_containers() {
  local listing
  if [[ -n "${TEST_DOCKER_PS_OUTPUT+x}" ]]; then
    listing="$TEST_DOCKER_PS_OUTPUT"
  elif command -v docker >/dev/null 2>&1; then
    listing="$(docker ps --format '{{.Label "com.docker.compose.project"}} {{.Names}}')"
  else
    listing=""
  fi
  awk 'NF && $1 != "ezopenpn" {print substr($0, 1, 160)}' <<<"$listing"
}

_firewall_state() {
  if [[ -n "${TEST_FIREWALL_STATE:-}" ]]; then
    printf '%s\n' "$TEST_FIREWALL_STATE"
    return
  fi
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    printf '%s\n' ufw
    return
  fi
  if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    printf '%s\n' firewalld
    return
  fi
  if command -v iptables >/dev/null 2>&1; then
    local input_policy
    input_policy="$(iptables -S INPUT 2>/dev/null | head -n 1 || true)"
    if [[ -n "$input_policy" && "$input_policy" != "-P INPUT ACCEPT" ]]; then
      printf '%s\n' raw
      return
    fi
  fi
  printf '%s\n' none
}

_network_is_reachable() {
  if [[ -n "${TEST_NETWORK_OK:-}" ]]; then
    [[ "$TEST_NETWORK_OK" == "1" ]]
    return
  fi
  local url status
  for url in \
    https://github.com/ \
    https://registry-1.docker.io/v2/ \
    https://acme-v02.api.letsencrypt.org/directory; do
    status="$(curl --proto '=https' --tlsv1.2 -sS -o /dev/null -w '%{http_code}' \
      --connect-timeout 5 --max-time 15 "$url")" || return 1
    [[ "$status" != "000" ]] || return 1
  done
}

_https_clock_date() {
  if [[ -n "${TEST_HTTPS_DATE+x}" ]]; then
    printf '%s\n' "$TEST_HTTPS_DATE"
    return
  fi
  curl --proto '=https' --tlsv1.2 -fsSL \
    --connect-timeout 5 --max-time 15 \
    -D - -o /dev/null https://github.com/ |
    awk '
      tolower($1) == "date:" {
        sub(/^[^:]*:[[:space:]]*/, "")
        gsub(/\r/, "")
        value = $0
      }
      END {
        if (value != "") print value
      }
    '
}

_clock_matches_https() {
  local remote_date now_epoch="${TEST_NOW_EPOCH:-}"
  remote_date="$(_https_clock_date)" || return 1
  [[ -n "$remote_date" ]] || return 1
  python3 - "$remote_date" "$now_epoch" <<'PY'
from __future__ import annotations

import math
import sys
import time
from email.utils import parsedate_to_datetime

try:
    remote = parsedate_to_datetime(sys.argv[1]).timestamp()
    current = float(sys.argv[2]) if sys.argv[2] else time.time()
except (OverflowError, TypeError, ValueError):
    raise SystemExit(1)
if not math.isfinite(remote) or not math.isfinite(current):
    raise SystemExit(1)
raise SystemExit(0 if abs(current - remote) <= 300 else 1)
PY
}

run_preflight() {
  local mode="install"
  local state_root="${EZOPENPN_STATE_ROOT:-/var/lib/ezopenpn}"
  if [[ -f "${state_root}/install.json" ]]; then
    mode="maintenance"
  elif [[ -f "${state_root}/operations/current.json" ]]; then
    if [[ "${EZOPENPN_ALLOW_INTERRUPTED_INSTALL:-}" == "1" ]]; then
      mode="maintenance"
    else
      _preflight_fail 29 "$mode" "" "E_PREFLIGHT_INTERRUPTED" \
        "обнаружена незавершённая операция"
      return
    fi
  fi

  local architecture="${TEST_UNAME_M:-$(uname -m)}"
  if [[ "$architecture" != "x86_64" && "$architecture" != "amd64" ]]; then
    _preflight_fail 20 "$mode" "" "E_PREFLIGHT_ARCH" \
      "поддерживается только архитектура amd64"
    return
  fi

  local os_release="${EZOPENPN_OS_RELEASE_PATH:-/etc/os-release}"
  if ! _supported_operating_system "$os_release"; then
    _preflight_fail 21 "$mode" "" "E_PREFLIGHT_OS" \
      "поддерживаются Ubuntu 22.04, Ubuntu 24.04, Debian 12 и Debian 13"
    return
  fi
  if [[ "${TEST_SYSTEMD:-}" != "1" && ! -d /run/systemd/system ]]; then
    _preflight_fail 21 "$mode" "" "E_PREFLIGHT_SYSTEMD" "systemd недоступен"
    return
  fi

  local effective_uid="${EZOPENPN_TEST_EUID:-${EUID:-$(id -u)}}"
  if [[ "$effective_uid" != "0" ]] && ! sudo -n true >/dev/null 2>&1; then
    _preflight_fail 21 "$mode" "" "E_PREFLIGHT_ROOT" \
      "нужны root или рабочий sudo"
    return
  fi

  local public_ip
  if ! public_ip="$(detect_public_ipv4)"; then
    _preflight_fail 22 "$mode" "" "E_PREFLIGHT_PUBLIC_IP" \
      "нужен напрямую назначенный публичный IPv4"
    return
  fi

  local memory_kib="${TEST_MEMORY_KIB:-}"
  if [[ -z "$memory_kib" ]]; then
    memory_kib="$(awk '/^MemTotal:/ {print $2; exit}' /proc/meminfo)"
  fi
  local disk_kib="${TEST_DISK_KIB:-}"
  if [[ -z "$disk_kib" ]]; then
    disk_kib="$(df -Pk /var | awk 'NR == 2 {print $4}')"
  fi
  if (( memory_kib < 1048576 || disk_kib < 4194304 )); then
    _preflight_fail 23 "$mode" "$public_ip" "E_PREFLIGHT_RESOURCES" \
      "нужно не менее 1 ГиБ памяти и 4 ГиБ свободного места"
    return
  fi

  local synchronized="${TEST_TIME_SYNC:-}"
  if [[ -z "$synchronized" ]]; then
    synchronized="$(timedatectl show -p SystemClockSynchronized --value 2>/dev/null || true)"
  fi
  case "$synchronized" in
    yes | Yes | YES | true | True | TRUE | 1) ;;
    *)
      if ! _clock_matches_https; then
        _preflight_fail 23 "$mode" "$public_ip" "E_PREFLIGHT_TIME" \
          "не удалось подтвердить правильность системного времени"
        return
      fi
      ;;
  esac

  local conflicts
  conflicts="$(_listener_conflicts "$(_socket_listing)")"
  if [[ "$mode" != "maintenance" && -n "$conflicts" ]]; then
    _preflight_fail 24 "$mode" "$public_ip" "E_PREFLIGHT_PORT" "$conflicts"
    return
  fi

  local foreign
  foreign="$(_foreign_containers)"
  if [[ -n "$foreign" ]]; then
    _preflight_fail 25 "$mode" "$public_ip" "E_PREFLIGHT_CONTAINERS" "$foreign"
    return
  fi

  local firewall
  firewall="$(_firewall_state)"
  if [[ "$firewall" == "raw" ]]; then
    _preflight_fail 28 "$mode" "$public_ip" "E_PREFLIGHT_FIREWALL" \
      "обнаружена неподдерживаемая ручная политика firewall"
    return
  fi
  if ! _network_is_reachable; then
    _preflight_fail 26 "$mode" "$public_ip" "E_PREFLIGHT_NETWORK" \
      "не пройдена проверка DNS и исходящего HTTPS"
    return
  fi

  _preflight_report true "$mode" "$public_ip" "" "сервер готов"
}
