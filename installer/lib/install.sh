#!/usr/bin/env bash

_INSTALL_PHASES=(
  preflight
  bundle_verified
  docker_ready
  firewall_ready
  layout_ready
  gateway_started
  certificate_ready
  control_migrated
  admin_created
  runtimes_ready
  external_checks_passed
  install_complete
)

INSTALL_LAB_CERTIFICATE=""
INSTALL_LAB_KEY=""
INSTALL_LAB_MODE=0
INSTALL_PUBLIC_IP=""
INSTALL_VERSION=""
INSTALL_ADMIN_LOGIN=""
INSTALL_RELEASE_ROOT=""
INSTALL_PREVIOUS_CURRENT=""

_install_host_path() {
  printf '%s%s\n' "${EZOPENPN_ROOT_PREFIX:-}" "$1"
}

_install_recommendation() {
  printf '%s\n' \
    "Первая рекомендация: используйте отдельный чистый VPS без сайтов и других сервисов."
}

_parse_install_arguments() {
  INSTALL_LAB_CERTIFICATE=""
  INSTALL_LAB_KEY=""
  INSTALL_LAB_MODE=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --advanced-lab-certificate)
        if [[ $# -lt 2 ]]; then
          die 2 "E_INSTALL_ARGUMENT: после --advanced-lab-certificate нужен путь"
          return
        fi
        INSTALL_LAB_CERTIFICATE="$2"
        shift 2
        ;;
      --advanced-lab-key)
        if [[ $# -lt 2 ]]; then
          die 2 "E_INSTALL_ARGUMENT: после --advanced-lab-key нужен путь"
          return
        fi
        INSTALL_LAB_KEY="$2"
        shift 2
        ;;
      *)
        die 2 "E_INSTALL_ARGUMENT: неизвестный параметр"
        return
        ;;
    esac
  done
  if [[ -n "$INSTALL_LAB_CERTIFICATE" && -z "$INSTALL_LAB_KEY" ]] || \
    [[ -z "$INSTALL_LAB_CERTIFICATE" && -n "$INSTALL_LAB_KEY" ]]; then
    die 2 "E_INSTALL_ARGUMENT: лабораторный сертификат и ключ задаются вместе"
    return
  fi
  if [[ -n "$INSTALL_LAB_CERTIFICATE" ]]; then
    if [[ "$INSTALL_LAB_CERTIFICATE" != /* || "$INSTALL_LAB_KEY" != /* || \
      ! -f "$INSTALL_LAB_CERTIFICATE" || -L "$INSTALL_LAB_CERTIFICATE" || \
      ! -f "$INSTALL_LAB_KEY" || -L "$INSTALL_LAB_KEY" ]]; then
      die 2 "E_INSTALL_ARGUMENT: лабораторные файлы должны быть обычными абсолютными путями"
      return
    fi
    INSTALL_LAB_MODE=1
  fi
}

_install_record_phase() {
  local phase="$1"
  if [[ -n "${TEST_INSTALL_EVENTS:-}" ]]; then
    printf '%s\n' "$phase" >>"$TEST_INSTALL_EVENTS"
  fi
  write_operation_checkpoint install "$phase"
}

_install_write_complete_state() {
  local destination="${EZOPENPN_STATE_ROOT:-/var/lib/ezopenpn}/install.json"
  mkdir -p "$(dirname "$destination")"
  if ! python3 - \
    "$destination" "$INSTALL_VERSION" "$INSTALL_PUBLIC_IP" \
    "$INSTALL_ADMIN_LOGIN" "$INSTALL_LAB_MODE" <<'PY'
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

destination = Path(sys.argv[1])
temporary = destination.with_name(destination.name + ".tmp")
payload = {
    "admin_login": sys.argv[4],
    "installed_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    "laboratory_mode": sys.argv[5] == "1",
    "public_ipv4": sys.argv[3],
    "version": sys.argv[2],
}
descriptor = os.open(
    temporary,
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
    0o600,
)
try:
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(payload, stream, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, destination)
    directory = os.open(destination.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
finally:
    temporary.unlink(missing_ok=True)
PY
  then
    die 55 "E_INSTALL_STATE: итоговое состояние не удалось сохранить"
    return
  fi
  chmod 0600 "$destination" || {
    die 55 "E_INSTALL_STATE: права итогового состояния не удалось установить"
    return
  }
}

_install_success_output() {
  printf '%s\n' \
    "EzOpenPN готов." \
    "Панель: https://${INSTALL_PUBLIC_IP}:9443" \
    "Логин: ${INSTALL_ADMIN_LOGIN}" \
    "Проверка: sudo ezopenpn status" \
    "Сброс пароля: sudo ezopenpn admin reset-password" \
    "В firewall провайдера разрешите 80/tcp, 443/tcp, 443/udp и 9443/tcp."
  if [[ "$INSTALL_LAB_MODE" == "1" ]]; then
    warn "Лабораторный сертификат может отклоняться браузерами и клиентами."
  fi
}

_install_test_rollback() {
  rm -f -- "${TEST_MANAGED_SERVICES:-/nonexistent}" \
    "${TEST_MANAGED_FIREWALL:-/nonexistent}"
}

_installer_main_test() {
  acquire_operation_lock install || return
  INSTALL_PUBLIC_IP=203.0.113.10
  INSTALL_VERSION=v0.1.0
  INSTALL_ADMIN_LOGIN=owner
  local phase status=0
  for phase in "${_INSTALL_PHASES[@]}"; do
    if [[ "${TEST_FAIL_PHASE:-}" == "$phase" ]]; then
      die 55 "E_INSTALL_PHASE: проверка этапа не пройдена"
      status=55
      break
    fi
    case "$phase" in
      firewall_ready) : >"$TEST_MANAGED_FIREWALL" ;;
      gateway_started) : >"$TEST_MANAGED_SERVICES" ;;
    esac
    _install_record_phase "$phase"
  done
  if (( status != 0 )); then
    _install_test_rollback
    release_operation_lock
    return "$status"
  fi
  _install_write_complete_state || {
    _install_test_rollback
    release_operation_lock
    return 55
  }
  clear_operation_checkpoint
  release_operation_lock
  _install_success_output
}

_install_resume_phase() {
  local checkpoint
  checkpoint="$(operation_checkpoint_path)"
  [[ -f "$checkpoint" ]] || return 1
  python3 - "$checkpoint" "${_INSTALL_PHASES[@]}" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

value = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if value.get("operation") != "install" or value.get("phase") not in sys.argv[2:]:
    raise SystemExit(1)
print(value["phase"])
PY
}

_install_phase_rank() {
  local wanted="$1"
  local index
  for index in "${!_INSTALL_PHASES[@]}"; do
    if [[ "${_INSTALL_PHASES[$index]}" == "$wanted" ]]; then
      printf '%s\n' "$index"
      return 0
    fi
  done
  return 1
}

_install_resumed_at_or_after() {
  local wanted="$1"
  [[ -n "${INSTALL_RESUME_PHASE:-}" ]] || return 1
  local resumed_rank wanted_rank
  resumed_rank="$(_install_phase_rank "$INSTALL_RESUME_PHASE")" || return 1
  wanted_rank="$(_install_phase_rank "$wanted")" || return 1
  (( resumed_rank >= wanted_rank ))
}

_install_manifest_version() {
  python3 - "$EZOPENPN_BUNDLE_ROOT/manifest.json" <<'PY'
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

manifest = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
version = manifest.get("version")
if not isinstance(version, str) or re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", version) is None:
    raise SystemExit(1)
print(version)
PY
}

_install_manifest_image() {
  local name="$1"
  python3 - "$EZOPENPN_BUNDLE_ROOT/manifest.json" "$name" <<'PY'
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

manifest = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
images = manifest.get("images")
if not isinstance(images, dict):
    raise SystemExit(1)
aliases = {
    "cert-sync": ("cert-sync", "cert_sync"),
    "control": ("control",),
    "gateway": ("gateway",),
    "hysteria": ("hysteria",),
    "xray": ("xray",),
}
item = None
for candidate in aliases[sys.argv[2]]:
    if candidate in images:
        item = images[candidate]
        break
if isinstance(item, str):
    reference = item
elif isinstance(item, dict):
    repository = item.get("reference") or item.get("repository")
    digest = item.get("digest")
    if not isinstance(repository, str) or not isinstance(digest, str):
        raise SystemExit(1)
    reference = repository if "@sha256:" in repository else f"{repository}@{digest}"
else:
    raise SystemExit(1)
if re.fullmatch(r"[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}", reference) is None:
    raise SystemExit(1)
print(reference)
PY
}

_verify_install_bundle() {
  if [[ "$EZOPENPN_BUNDLE_ROOT" != /* || ! -d "$EZOPENPN_BUNDLE_ROOT" || \
    -L "$EZOPENPN_BUNDLE_ROOT" || ! -f "$EZOPENPN_BUNDLE_ROOT/manifest.json" || \
    ! -d "$EZOPENPN_BUNDLE_ROOT/deploy" || ! -d "$EZOPENPN_BUNDLE_ROOT/installer" ]]; then
    die 31 "E_RELEASE_VERIFY: проверенный пакет недоступен"
    return
  fi
  INSTALL_VERSION="$(_install_manifest_version)" || {
    die 31 "E_RELEASE_VERIFY: manifest выпуска повреждён"
    return
  }
  INSTALL_CONTROL_IMAGE="$(_install_manifest_image control)" || {
    die 31 "E_RELEASE_VERIFY: образ control не закреплён"
    return
  }
  INSTALL_XRAY_IMAGE="$(_install_manifest_image xray)" || {
    die 31 "E_RELEASE_VERIFY: образ xray не закреплён"
    return
  }
  INSTALL_HYSTERIA_IMAGE="$(_install_manifest_image hysteria)" || {
    die 31 "E_RELEASE_VERIFY: образ hysteria не закреплён"
    return
  }
  INSTALL_GATEWAY_IMAGE="$(_install_manifest_image gateway)" || {
    die 31 "E_RELEASE_VERIFY: образ gateway не закреплён"
    return
  }
  INSTALL_CERT_SYNC_IMAGE="$(_install_manifest_image cert-sync)" || {
    die 31 "E_RELEASE_VERIFY: образ cert-sync не закреплён"
    return
  }
}

_install_release_files() {
  local releases_root current_path
  releases_root="$(_install_host_path /etc/ezopenpn/releases)"
  current_path="$(_install_host_path /etc/ezopenpn/current)"
  INSTALL_RELEASE_ROOT="${releases_root}/${INSTALL_VERSION}"
  INSTALL_PREVIOUS_CURRENT=""
  if [[ -L "$current_path" ]]; then
    INSTALL_PREVIOUS_CURRENT="$(readlink "$current_path")"
    if [[ ! "$INSTALL_PREVIOUS_CURRENT" =~ ^releases/v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      die 45 "E_RELEASE_PATH: current указывает на неожиданный путь"
      return
    fi
  elif [[ -e "$current_path" ]]; then
    die 45 "E_RELEASE_PATH: current занят другим объектом"
    return
  fi

  if ! python3 - \
    "$EZOPENPN_BUNDLE_ROOT" "$releases_root" "$INSTALL_VERSION" <<'PY'
from __future__ import annotations

import filecmp
import os
import shutil
import stat
import sys
import tempfile
from pathlib import Path

source = Path(sys.argv[1])
parent = Path(sys.argv[2])
version = sys.argv[3]
destination = parent / version
allowlist = ("deploy", "installer", "manifest.json", "LICENSE", "THIRD_PARTY_NOTICES.md")


def reject_links(path: Path) -> None:
    for root, directories, files in os.walk(path, followlinks=False):
        for name in [*directories, *files]:
            candidate = Path(root) / name
            if candidate.is_symlink():
                raise SystemExit(1)


def same_tree(left: Path, right: Path) -> bool:
    comparison = filecmp.dircmp(left, right)
    if comparison.left_only or comparison.right_only or comparison.funny_files:
        return False
    if any(not filecmp.cmp(left / name, right / name, shallow=False) for name in comparison.common_files):
        return False
    return all(same_tree(left / name, right / name) for name in comparison.common_dirs)


reject_links(source)
staging = Path(tempfile.mkdtemp(prefix=f".{version}.staging-", dir=parent))
try:
    for name in allowlist:
        item = source / name
        if not item.exists():
            continue
        target = staging / name
        if item.is_dir():
            shutil.copytree(item, target)
        elif item.is_file():
            shutil.copy2(item, target)
        else:
            raise SystemExit(1)
    if not (staging / "deploy" / "compose.yaml").is_file():
        raise SystemExit(1)
    if not (staging / "installer" / "installer-main.sh").is_file():
        raise SystemExit(1)
    for root, directories, files in os.walk(staging):
        for name in directories:
            os.chmod(Path(root) / name, 0o755)
        for name in files:
            path = Path(root) / name
            mode = 0o755 if path.suffix == ".sh" or path.name == "ezopenpn" else 0o644
            os.chmod(path, mode)
    if destination.exists():
        if destination.is_symlink() or not destination.is_dir() or not same_tree(staging, destination):
            raise SystemExit(1)
        shutil.rmtree(staging)
    else:
        os.replace(staging, destination)
    directory = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
finally:
    if staging.exists():
        shutil.rmtree(staging)
PY
  then
    die 45 "E_RELEASE_PATH: файлы выпуска не удалось установить безопасно"
    return
  fi

  if ! python3 - "$current_path" "$INSTALL_VERSION" <<'PY'
from __future__ import annotations

import os
import sys
from pathlib import Path

current = Path(sys.argv[1])
temporary = current.with_name(current.name + ".tmp")
try:
    temporary.unlink()
except FileNotFoundError:
    pass
os.symlink(f"releases/{sys.argv[2]}", temporary)
try:
    os.replace(temporary, current)
    directory = os.open(current.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
finally:
    try:
        temporary.unlink()
    except FileNotFoundError:
        pass
PY
  then
    die 45 "E_RELEASE_PATH: current не удалось переключить"
    return
  fi
}

_install_stack_environment() {
  local destination
  destination="$(_install_host_path /etc/ezopenpn/stack.env)"
  python3 - \
    "$destination" "$INSTALL_PUBLIC_IP" "$INSTALL_CONTROL_IMAGE" \
    "$INSTALL_XRAY_IMAGE" "$INSTALL_HYSTERIA_IMAGE" "$INSTALL_GATEWAY_IMAGE" \
    "$INSTALL_CERT_SYNC_IMAGE" <<'PY'
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

destination = Path(sys.argv[1])
names = (
    "PUBLIC_IP",
    "CONTROL_IMAGE",
    "XRAY_IMAGE",
    "HYSTERIA_IMAGE",
    "GATEWAY_IMAGE",
    "CERT_SYNC_IMAGE",
)
values = sys.argv[2:]
if len(values) != len(names):
    raise SystemExit(1)
if re.fullmatch(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", values[0]) is None:
    raise SystemExit(1)
if any("\n" in value or "\r" in value for value in values):
    raise SystemExit(1)
temporary = destination.with_name(destination.name + ".tmp")
descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
try:
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        for name, value in zip(names, values):
            stream.write(f"{name}={value}\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, destination)
finally:
    temporary.unlink(missing_ok=True)
PY
  chmod 0640 "$destination"
  _configure_chown root:root "$destination"
}

_install_laboratory_certificate() {
  [[ "$INSTALL_LAB_MODE" == "1" ]] || return 0
  local laboratory_root
  laboratory_root="$(_install_host_path /var/lib/ezopenpn/caddy/lab)"
  install -d -m 0700 "$laboratory_root"
  install -m 0600 "$INSTALL_LAB_CERTIFICATE" "${laboratory_root}/server.crt"
  install -m 0600 "$INSTALL_LAB_KEY" "${laboratory_root}/server.key"
  _configure_chown 10004:11003 "$laboratory_root"
  _configure_chown 10004:11003 "${laboratory_root}/server.crt"
  _configure_chown 10004:11003 "${laboratory_root}/server.key"
  install -m 0640 "${INSTALL_RELEASE_ROOT}/installer/lab/Caddyfile" \
    "$(_install_host_path /etc/ezopenpn/Caddyfile)"
  _configure_chown root:11003 "$(_install_host_path /etc/ezopenpn/Caddyfile)"
}

_validate_laboratory_pair() {
  [[ "$INSTALL_LAB_MODE" == "1" ]] || return 0
  local certificate_public key_public
  certificate_public="$(openssl x509 -in "$INSTALL_LAB_CERTIFICATE" -pubkey -noout 2>/dev/null | \
    openssl sha256 2>/dev/null)" || return 2
  key_public="$(openssl pkey -in "$INSTALL_LAB_KEY" -pubout 2>/dev/null | \
    openssl sha256 2>/dev/null)" || return 2
  if [[ -z "$certificate_public" || "$certificate_public" != "$key_public" ]] || \
    ! openssl x509 -in "$INSTALL_LAB_CERTIFICATE" -text -noout 2>/dev/null | \
      python3 -c \
        'import ipaddress,re,sys; wanted=ipaddress.ip_address(sys.argv[1]); values=[ipaddress.ip_address(value) for value in re.findall(r"IP Address:\s*([0-9.]+)", sys.stdin.read())]; raise SystemExit(0 if wanted in values else 1)' \
        "$INSTALL_PUBLIC_IP"; then
    die 2 "E_LAB_CERTIFICATE: ключ или IP SAN не совпадают"
    return
  fi
  local tty_input="${EZOPENPN_TTY_INPUT_PATH:-${EZOPENPN_TTY_PATH:-/dev/tty}}"
  local tty_output="${EZOPENPN_TTY_OUTPUT_PATH:-${EZOPENPN_TTY_PATH:-/dev/tty}}"
  local confirmation
  printf '%s' 'Лабораторный режим не даёт обычной проверки доверия. Введите LAB: ' \
    >>"$tty_output"
  if ! IFS= read -r confirmation <"$tty_input" || [[ "$confirmation" != "LAB" ]]; then
    die 2 "E_LAB_CONFIRMATION: лабораторный режим не подтверждён"
    return
  fi
}

_install_compose() {
  docker compose \
    --env-file "$(_install_host_path /etc/ezopenpn/stack.env)" \
    -f "$(_install_host_path /etc/ezopenpn/compose.yaml)" \
    --project-name ezopenpn "$@"
}

_wait_service_healthy() {
  local service="$1"
  local timeout_seconds="${2:-180}"
  local deadline=$((SECONDS + timeout_seconds))
  local container_id health
  while (( SECONDS < deadline )); do
    container_id="$(_install_compose ps -q "$service" 2>/dev/null || true)"
    if [[ -n "$container_id" ]]; then
      health="$(docker inspect --format \
        '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' \
        "$container_id" 2>/dev/null || true)"
      if [[ "$health" == "healthy" ]]; then
        return 0
      fi
      if [[ "$health" == "exited" || "$health" == "dead" ]]; then
        break
      fi
    fi
    sleep 2
  done
  die 55 "E_HEALTH_TIMEOUT: сервис ${service} не готов"
}

_wait_panel_tls() {
  local deadline=$((SECONDS + 240))
  local curl_arguments=(
    --proto '=https'
    --tlsv1.2
    -sS
    -o /dev/null
    --connect-timeout 5
    --max-time 10
  )
  if [[ "$INSTALL_LAB_MODE" == "1" ]]; then
    curl_arguments+=(-k)
  fi
  while (( SECONDS < deadline )); do
    if curl "${curl_arguments[@]}" \
      "https://${INSTALL_PUBLIC_IP}:9443/health/live"; then
      return 0
    fi
    sleep 3
  done
  die 55 "E_CERTIFICATE_TIMEOUT: сертификат панели не готов"
}

_start_gateway_and_exporter() {
  _install_compose up -d --no-deps gateway cert-sync >/dev/null || return
  _wait_service_healthy gateway 120
}

_wait_certificate_ready() {
  _wait_service_healthy cert-sync 240 || return
  _wait_panel_tls
}

_migrate_control() {
  _install_compose up -d --no-deps control >/dev/null || return
  _wait_service_healthy control 120 || return
  _install_compose exec -T control python -m ezopenpn.cli \
    --config /etc/ezopenpn/control.toml migrate >/dev/null
}

_existing_admin_login() {
  local database
  database="$(_install_host_path /var/lib/ezopenpn/control/ezopenpn.sqlite3)"
  [[ -f "$database" && ! -L "$database" ]] || return 1
  python3 - "$database" <<'PY'
from __future__ import annotations

import sqlite3
import sys

try:
    connection = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
    row = connection.execute("SELECT login FROM admins WHERE singleton_key = 1").fetchone()
finally:
    try:
        connection.close()
    except NameError:
        pass
if row is None or not isinstance(row[0], str) or not row[0]:
    raise SystemExit(1)
print(row[0])
PY
}

_record_operation_admin_login() {
  local login="$1"
  local destination="${EZOPENPN_STATE_ROOT:-/var/lib/ezopenpn}/operations/admin-login"
  if [[ -z "$login" || "$login" == *$'\n'* || "$login" == *$'\r'* ]]; then
    return 1
  fi
  printf '%s\n' "$login" >"${destination}.tmp"
  chmod 0600 "${destination}.tmp"
  mv -f -- "${destination}.tmp" "$destination"
}

_create_or_recover_admin() {
  local current_login
  if current_login="$(_existing_admin_login 2>/dev/null)"; then
    INSTALL_ADMIN_LOGIN="$current_login"
    _record_operation_admin_login "$INSTALL_ADMIN_LOGIN"
    return 0
  fi
  if _install_resumed_at_or_after admin_created; then
    die 55 "E_ADMIN_STATE: checkpoint и хранилище администратора расходятся"
    return
  fi
  initialize_admin_from_tty \
    _install_compose exec -T control python -m ezopenpn.cli \
    --config /etc/ezopenpn/control.toml || return
  INSTALL_ADMIN_LOGIN="$INITIAL_ADMIN_LOGIN"
  _record_operation_admin_login "$INSTALL_ADMIN_LOGIN"
}

_start_runtimes() {
  _install_compose up -d --no-deps xray >/dev/null || return
  _wait_service_healthy xray 120 || return
  _install_compose up -d hysteria >/dev/null || return
  _wait_service_healthy hysteria 120 || return
  _install_compose restart control >/dev/null || return
  _wait_service_healthy control 120
}

_run_external_checks() {
  local curl_arguments=(
    --proto '=https'
    --tlsv1.2
    -fsS
    -o /dev/null
    --connect-timeout 5
    --max-time 15
  )
  if [[ "$INSTALL_LAB_MODE" == "1" ]]; then
    curl_arguments+=(-k)
  fi
  curl "${curl_arguments[@]}" \
    "https://${INSTALL_PUBLIC_IP}:9443/health/ready"
}

_install_systemd_and_cli() {
  local unit_directory unit_path cli_path
  unit_directory="$(_install_host_path /etc/systemd/system)"
  unit_path="${unit_directory}/ezopenpn.service"
  cli_path="$(_install_host_path /usr/local/bin/ezopenpn)"
  install -d -m 0755 "$unit_directory" "$(dirname "$cli_path")"
  install -m 0644 "${INSTALL_RELEASE_ROOT}/installer/systemd/ezopenpn.service" "$unit_path"
  if [[ -f "${INSTALL_RELEASE_ROOT}/installer/bin/ezopenpn" ]]; then
    install -m 0755 "${INSTALL_RELEASE_ROOT}/installer/bin/ezopenpn" "$cli_path"
  fi
  systemctl daemon-reload
  systemctl enable ezopenpn.service >/dev/null
  systemctl start ezopenpn.service
}

_prepare_installed_layout() {
  configure_layout || return
  _install_release_files || return
  configure_runtime_material \
    "${INSTALL_RELEASE_ROOT}/installer/targets.txt" "$INSTALL_XRAY_IMAGE" || return
  render_server_configuration "$INSTALL_PUBLIC_IP" "$INSTALL_RELEASE_ROOT" || return
  _install_stack_environment || return
  _install_laboratory_certificate || return
  _install_compose pull >/dev/null || return
}

_rollback_production_install() {
  systemctl disable --now ezopenpn.service >/dev/null 2>&1 || true
  if [[ -f "$(_install_host_path /etc/ezopenpn/stack.env)" && \
    -f "$(_install_host_path /etc/ezopenpn/compose.yaml)" ]]; then
    _install_compose down --remove-orphans >/dev/null 2>&1 || true
  fi
  rollback_firewall_rules || true
  local current_path
  current_path="$(_install_host_path /etc/ezopenpn/current)"
  if [[ -n "$INSTALL_PREVIOUS_CURRENT" ]]; then
    local temporary_link="${current_path}.rollback"
    rm -f -- "$temporary_link"
    ln -s "$INSTALL_PREVIOUS_CURRENT" "$temporary_link"
    mv -f -- "$temporary_link" "$current_path"
  fi
}

_run_production_install() {
  local preflight_report
  if [[ -n "${INSTALL_RESUME_PHASE:-}" ]]; then
    if ! preflight_report="$(EZOPENPN_ALLOW_INTERRUPTED_INSTALL=1 run_preflight)"; then
      printf '%s\n' "$preflight_report" >&2
      return 22
    fi
  elif ! preflight_report="$(run_preflight)"; then
    printf '%s\n' "$preflight_report" >&2
    return 22
  fi
  INSTALL_PUBLIC_IP="$(python3 -c \
    'import json,sys; value=json.load(sys.stdin); assert value["ok"]; print(value["public_ipv4"])' \
    <<<"$preflight_report")" || return 22
  _validate_laboratory_pair || return
  _install_record_phase preflight || return

  _verify_install_bundle || return
  _install_record_phase bundle_verified || return

  ensure_docker_engine || return
  _install_record_phase docker_ready || return

  apply_firewall_rules || return
  _install_record_phase firewall_ready || return

  _prepare_installed_layout || return
  _install_record_phase layout_ready || return

  _start_gateway_and_exporter || return
  _install_record_phase gateway_started || return

  _wait_certificate_ready || return
  _install_record_phase certificate_ready || return

  _migrate_control || return
  _install_record_phase control_migrated || return

  _create_or_recover_admin || return
  _install_record_phase admin_created || return

  _start_runtimes || return
  _install_record_phase runtimes_ready || return

  _install_systemd_and_cli || return
  _run_external_checks || return
  _install_record_phase external_checks_passed || return

  _install_record_phase install_complete || return
  _install_write_complete_state || return
  clear_operation_checkpoint
  rm -f -- "${EZOPENPN_STATE_ROOT:-/var/lib/ezopenpn}/operations/admin-login"
}

installer_main() {
  _install_recommendation
  _parse_install_arguments "$@" || return
  if [[ "${TEST_INSTALL_FLOW:-}" == "1" ]]; then
    _installer_main_test
    return
  fi

  require_root || return
  require_tty || return
  acquire_operation_lock install || return
  INSTALL_RESUME_PHASE="$(_install_resume_phase 2>/dev/null || true)"
  if [[ -f "$(operation_checkpoint_path)" && -z "$INSTALL_RESUME_PHASE" ]]; then
    release_operation_lock
    die 55 "E_INSTALL_CHECKPOINT: незавершённая операция повреждена"
    return
  fi

  local status=0
  _run_production_install || status=$?
  if (( status != 0 )); then
    _rollback_production_install
    release_operation_lock
    return "$status"
  fi
  release_operation_lock
  _install_success_output
}
