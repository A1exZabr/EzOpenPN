#!/usr/bin/env bash

_diagnostic_path() {
  printf '%s%s\n' "${EZOPENPN_ROOT_PREFIX:-}" "$1"
}

_diagnostic_install_state() {
  _diagnostic_path /var/lib/ezopenpn/install.json
}

_diagnostic_require_installation() {
  local state
  state="$(_diagnostic_install_state)"
  if [[ ! -f "$state" || -L "$state" || \
    ! -f "$(_diagnostic_path /etc/ezopenpn/compose.yaml)" || \
    ! -f "$(_diagnostic_path /etc/ezopenpn/stack.env)" ]]; then
    die 3 "E_INSTALL_UNAVAILABLE: установка EzOpenPN не найдена"
    return
  fi
}

_diagnostic_state_field() {
  local field="$1"
  python3 - "$(_diagnostic_install_state)" "$field" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

value = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
result = value.get(sys.argv[2])
if isinstance(result, bool):
    print("true" if result else "false")
elif isinstance(result, (str, int)):
    print(result)
else:
    raise SystemExit(1)
PY
}

_diagnostic_compose() {
  docker compose \
    --env-file "$(_diagnostic_path /etc/ezopenpn/stack.env)" \
    -f "$(_diagnostic_path /etc/ezopenpn/compose.yaml)" \
    --project-name ezopenpn "$@"
}

_diagnostic_test_health() {
  case "$1" in
    control) printf '%s\n' "${TEST_HEALTH_CONTROL:-}" ;;
    xray) printf '%s\n' "${TEST_HEALTH_XRAY:-}" ;;
    hysteria) printf '%s\n' "${TEST_HEALTH_HYSTERIA:-}" ;;
    gateway) printf '%s\n' "${TEST_HEALTH_GATEWAY:-}" ;;
    cert-sync) printf '%s\n' "${TEST_HEALTH_CERT_SYNC:-}" ;;
  esac
}

_diagnostic_service_health() {
  local service="$1"
  if [[ -n "${TEST_HEALTH_CONTROL:-}" ]]; then
    _diagnostic_test_health "$service"
    return
  fi
  local container_id
  container_id="$(_diagnostic_compose ps -q "$service" 2>/dev/null || true)"
  if [[ -z "$container_id" ]]; then
    printf '%s\n' missing
    return
  fi
  docker inspect --format \
    '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' \
    "$container_id" 2>/dev/null || printf '%s\n' unavailable
}

_diagnostic_certificate_expiry() {
  if [[ -n "${TEST_CERTIFICATE_EXPIRY:-}" ]]; then
    printf '%s\n' "$TEST_CERTIFICATE_EXPIRY"
    return
  fi
  local health
  health="$(_diagnostic_path /var/lib/ezopenpn/runtime/hysteria-certs/health.json)"
  [[ -f "$health" && ! -L "$health" ]] || return 1
  python3 - "$health" <<'PY'
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

value = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
expiry = value.get("not_after")
if not isinstance(expiry, str):
    raise SystemExit(1)
parsed = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
if parsed.tzinfo is None or parsed <= datetime.now(timezone.utc):
    raise SystemExit(1)
print(expiry)
PY
}

_diagnostic_active_profiles() {
  if [[ -n "${TEST_ACTIVE_PROFILES:-}" ]]; then
    printf '%s\n' "$TEST_ACTIVE_PROFILES"
    return
  fi
  local database
  database="$(_diagnostic_path /var/lib/ezopenpn/control/ezopenpn.sqlite3)"
  [[ -f "$database" && ! -L "$database" ]] || return 1
  python3 - "$database" <<'PY'
from __future__ import annotations

import sqlite3
import sys

connection = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
try:
    result = connection.execute(
        "SELECT COUNT(*) FROM profiles WHERE state = 'active'"
    ).fetchone()
finally:
    connection.close()
if result is None or not isinstance(result[0], int):
    raise SystemExit(1)
print(result[0])
PY
}

_diagnostic_public_ready() {
  if [[ -n "${TEST_PANEL_READY:-}" ]]; then
    [[ "$TEST_PANEL_READY" == "1" ]]
    return
  fi
  local public_ip laboratory
  public_ip="$(_diagnostic_state_field public_ipv4)" || return 1
  laboratory="$(_diagnostic_state_field laboratory_mode)" || return 1
  local arguments=(
    --proto '=https'
    --tlsv1.2
    -fsS
    -o /dev/null
    --connect-timeout 5
    --max-time 15
  )
  if [[ "$laboratory" == true ]]; then
    arguments+=(-k)
  fi
  curl "${arguments[@]}" "https://${public_ip}:9443/health/ready"
}

diagnostic_status() {
  _diagnostic_require_installation || return
  local version public_ip expiry profiles service health degraded=0
  version="$(_diagnostic_state_field version)" || return 3
  public_ip="$(_diagnostic_state_field public_ipv4)" || return 3
  printf 'Версия: %s\n' "$version"
  printf 'Панель: https://%s:9443\n' "$public_ip"
  for service in control xray hysteria gateway cert-sync; do
    health="$(_diagnostic_service_health "$service")"
    printf '%s: %s\n' "$service" "$health"
    [[ "$health" == healthy ]] || degraded=1
  done
  if expiry="$(_diagnostic_certificate_expiry)"; then
    printf 'Сертификат действует до: %s\n' "$expiry"
  else
    printf '%s\n' 'Сертификат: недоступен'
    degraded=1
  fi
  if profiles="$(_diagnostic_active_profiles)"; then
    printf 'Активных профилей: %s\n' "$profiles"
  else
    printf '%s\n' 'Активных профилей: неизвестно'
    degraded=1
  fi
  if ! _diagnostic_public_ready >/dev/null 2>&1; then
    degraded=1
  fi
  if (( degraded == 0 )); then
    printf '%s\n' 'Итог: готово'
    return 0
  fi
  printf '%s\n' 'Итог: есть проблемы'
  return 1
}

_doctor_test_value() {
  case "$1" in
    preflight) [[ "${TEST_DOCTOR_PREFLIGHT:-}" == "1" ]] ;;
    permissions) [[ "${TEST_DOCTOR_PERMISSIONS:-}" == "1" ]] ;;
    compose) [[ "${TEST_DOCTOR_COMPOSE:-}" == "1" ]] ;;
    database) [[ "${TEST_DOCTOR_DATABASE:-}" == "1" ]] ;;
    certificate) [[ "${TEST_DOCTOR_CERTIFICATE:-}" == "1" ]] ;;
    reconcile) [[ "${TEST_DOCTOR_RECONCILE:-}" == "1" ]] ;;
    public_https) [[ "${TEST_DOCTOR_PUBLIC:-}" == "1" ]] ;;
    *) return 1 ;;
  esac
}

_doctor_permissions() {
  python3 - \
    "$(_diagnostic_path /etc/ezopenpn/control.toml)" \
    "$(_diagnostic_path /var/lib/ezopenpn/secrets/master.key)" \
    "$(_diagnostic_path /var/lib/ezopenpn/secrets/hysteria-api.key)" \
    "$(_diagnostic_path /var/lib/ezopenpn/secrets/hysteria-obfs.key)" \
    "$(_diagnostic_path /var/lib/ezopenpn/runtime/xray/config.json)" \
    "$(_diagnostic_path /var/lib/ezopenpn/runtime/hysteria/config.yaml)" <<'PY'
from __future__ import annotations

import stat
import sys
from pathlib import Path

expected = (0o640, 0o600, 0o600, 0o600, 0o600, 0o600)
for raw, mode in zip(sys.argv[1:], expected):
    path = Path(raw)
    status = path.lstat()
    if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
        raise SystemExit(1)
    if stat.S_IMODE(status.st_mode) != mode:
        raise SystemExit(1)
PY
}

_doctor_database() {
  local database
  database="$(_diagnostic_path /var/lib/ezopenpn/control/ezopenpn.sqlite3)"
  [[ -f "$database" && ! -L "$database" ]] || return 1
  python3 - "$database" <<'PY'
import sqlite3
import sys

connection = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
try:
    value = connection.execute("PRAGMA quick_check").fetchone()
finally:
    connection.close()
raise SystemExit(0 if value == ("ok",) else 1)
PY
}

_doctor_reconcile() {
  local service
  for service in control xray hysteria; do
    [[ "$(_diagnostic_service_health "$service")" == healthy ]] || return 1
  done
}

_doctor_check() {
  local name="$1"
  if [[ -n "${TEST_DOCTOR_PREFLIGHT:-}" ]]; then
    _doctor_test_value "$name"
    return
  fi
  case "$name" in
    preflight) run_preflight >/dev/null ;;
    permissions) _doctor_permissions ;;
    compose) _diagnostic_compose config --quiet >/dev/null ;;
    database) _doctor_database ;;
    certificate)
      _diagnostic_compose exec -T cert-sync /usr/local/bin/cert-sync \
        --healthcheck /hysteria-certs/health.json --min-validity 30m >/dev/null
      ;;
    reconcile) _doctor_reconcile ;;
    public_https) _diagnostic_public_ready >/dev/null ;;
    *) return 1 ;;
  esac
}

diagnostic_doctor() {
  _diagnostic_require_installation || return
  local name degraded=0
  for name in preflight permissions compose database certificate reconcile public_https; do
    if _doctor_check "$name" >/dev/null 2>&1; then
      printf '%s: ok\n' "$name"
    else
      printf '%s: failed\n' "$name"
      degraded=1
    fi
  done
  return "$degraded"
}

_diagnostic_raw_logs() {
  local service="$1"
  local since="$2"
  local tail_count="$3"
  if [[ -n "${TEST_LOG_OUTPUT:-}" ]]; then
    printf '%s\n' "$TEST_LOG_OUTPUT"
    return
  fi
  _diagnostic_compose logs --no-color --since "${since}s" --tail "$tail_count" \
    "$service"
}

_redact_diagnostic_stream() {
  local installer_root sanitizer
  installer_root="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
  sanitizer="${installer_root}/sanitize_logs.py"
  if [[ ! -f "$sanitizer" || -L "$sanitizer" ]]; then
    die 3 "E_LOG_SANITIZER: фильтр логов не найден"
    return
  fi
  python3 "$sanitizer" \
    "$(_diagnostic_path /var/lib/ezopenpn/secrets/master.key)" \
    "$(_diagnostic_path /var/lib/ezopenpn/secrets/hysteria-api.key)" \
    "$(_diagnostic_path /var/lib/ezopenpn/secrets/hysteria-obfs.key)" \
    "$(_diagnostic_path /var/lib/ezopenpn/runtime/xray/config.json)"
}

diagnostic_logs() {
  _diagnostic_require_installation || return
  local service="${1:-}"
  local since="${2:-3600}"
  local tail_count="${3:-200}"
  case "$service" in
    control | xray | hysteria | gateway | cert-sync) ;;
    *)
      die 2 \
        "E_LOG_SERVICE: выберите control, xray, hysteria, gateway, cert-sync"
      return
      ;;
  esac
  if [[ ! "$since" =~ ^[0-9]+$ || ! "$tail_count" =~ ^[0-9]+$ ]] || \
    (( since < 1 || since > 604800 || tail_count < 1 || tail_count > 10000 )); then
    die 2 "E_LOG_ARGUMENT: --since и --tail должны быть ограниченными числами"
    return
  fi
  _diagnostic_raw_logs "$service" "$since" "$tail_count" | \
    _redact_diagnostic_stream
}
