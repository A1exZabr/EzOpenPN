#!/usr/bin/env bash

_configure_path() {
  printf '%s%s\n' "${EZOPENPN_ROOT_PREFIX:-}" "$1"
}

_configure_chown() {
  local owner="$1"
  local path="$2"
  if [[ -n "${TEST_CHOWN_LOG:-}" ]]; then
    printf '%s %s\n' "$owner" "$path" >>"$TEST_CHOWN_LOG"
    return
  fi
  chown -- "$owner" "$path"
}

_configure_directory() {
  local relative_path="$1"
  local owner="$2"
  local mode="$3"
  local path
  path="$(_configure_path "$relative_path")"
  if [[ -L "$path" || ( -e "$path" && ! -d "$path" ) ]]; then
    die 45 "E_LAYOUT_PATH: каталог установки занят другим объектом"
    return
  fi
  install -d -m "$mode" "$path"
  chmod "$mode" "$path"
  _configure_chown "$owner" "$path"
}

_configure_secret() {
  local relative_path="$1"
  local path
  path="$(_configure_path "$relative_path")"
  if ! python3 - "$path" <<'PY'
from __future__ import annotations

import os
import secrets
import stat
import sys
from pathlib import Path

path = Path(sys.argv[1])
try:
    status = path.lstat()
except FileNotFoundError:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        value = secrets.token_bytes(32)
        written = 0
        while written < len(value):
            written += os.write(descriptor, value[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
else:
    if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
        raise SystemExit(1)
    if stat.S_IMODE(status.st_mode) != 0o600 or status.st_size != 32:
        raise SystemExit(1)
PY
  then
    die 45 "E_SECRET_FILE: существующий файл секрета небезопасен"
    return
  fi
  _configure_chown "10001:10001" "$path"
}

configure_layout() {
  _configure_directory /etc/ezopenpn root:root 0750
  _configure_directory /etc/ezopenpn/releases root:root 0750
  _configure_directory /var/lib/ezopenpn root:root 0700
  _configure_directory /var/lib/ezopenpn/control 10001:10001 0700
  _configure_directory /var/lib/ezopenpn/secrets 10001:10001 0700
  _configure_directory /var/lib/ezopenpn/operations root:root 0700
  _configure_directory /var/lib/ezopenpn/runtime root:root 0711
  _configure_directory /var/lib/ezopenpn/runtime/xray 10002:11001 0700
  _configure_directory /var/lib/ezopenpn/runtime/xray-run 10002:11001 0750
  _configure_directory /var/lib/ezopenpn/runtime/hysteria 10003:11003 0700
  _configure_directory /var/lib/ezopenpn/runtime/hysteria-certs 10004:11003 0750
  _configure_directory /var/lib/ezopenpn/caddy 10004:11003 0700
  _configure_directory /var/backups/ezopenpn root:root 0700

  _configure_secret /var/lib/ezopenpn/secrets/master.key
  _configure_secret /var/lib/ezopenpn/secrets/hysteria-api.key
  _configure_secret /var/lib/ezopenpn/secrets/hysteria-obfs.key
}

_require_digest_image() {
  local image="$1"
  if [[ "$image" =~ [[:space:]] || \
    ! "$image" =~ ^[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}$ ]]; then
    die 45 "E_IMAGE_REFERENCE: образ должен быть закреплён digest"
    return
  fi
}

_run_xray() {
  local image="$1"
  shift
  if [[ -n "${TEST_XRAY_BIN:-}" ]]; then
    "$TEST_XRAY_BIN" "$@"
    return
  fi
  local network=bridge
  if [[ "${1:-}" == x25519 ]]; then
    network=none
  fi
  docker run --rm \
    --network "$network" \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --pids-limit 64 \
    --memory 128m \
    --entrypoint /usr/local/bin/xray \
    "$image" "$@"
}

_normalize_target_name() {
  python3 - "$1" <<'PY'
from __future__ import annotations

import re
import sys

value = sys.argv[1].strip().lower()
pattern = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
)
if pattern.fullmatch(value) is None:
    raise SystemExit(1)
print(value)
PY
}

select_reality_target() {
  local targets_path="$1"
  local image="$2"
  if [[ ! -f "$targets_path" || -L "$targets_path" ]]; then
    die 44 "E_TARGET_LIST: список проверяемых узлов недоступен"
    return
  fi
  _require_digest_image "$image" || return

  local line candidate output success_count version_count
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"
    if ! candidate="$(_normalize_target_name "$line" 2>/dev/null)"; then
      continue
    fi
    if ! output="$(_run_xray "$image" tls ping "${candidate}:443" 2>&1)"; then
      continue
    fi
    success_count="$(grep -c 'Handshake succeeded' <<<"$output" || true)"
    version_count="$(grep -c 'TLS Version:.*TLS 1\.3' <<<"$output" || true)"
    if (( success_count >= 2 && version_count >= 2 )) && \
      grep -q 'Pinging with SNI' <<<"$output" && \
      grep -q 'TLS ping finished' <<<"$output"; then
      REALITY_SERVER_NAME="$candidate"
      REALITY_TARGET="${candidate}:443"
      return 0
    fi
  done <"$targets_path"

  die 44 "E_TARGET_UNAVAILABLE: не найден подходящий TLS 1.3 узел"
}

_validate_runtime_material() {
  local material_root="$1"
  python3 - "$material_root" <<'PY'
from __future__ import annotations

import base64
import json
import re
import stat
import sys
from pathlib import Path

root = Path(sys.argv[1])
if root.is_symlink() or not root.is_dir():
    raise SystemExit(1)
for name in ("runtime-values.json", "node.json"):
    path = root / name
    status = path.lstat()
    if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
        raise SystemExit(1)
    if stat.S_IMODE(status.st_mode) != 0o600:
        raise SystemExit(1)
runtime = json.loads((root / "runtime-values.json").read_text(encoding="utf-8"))
node = json.loads((root / "node.json").read_text(encoding="utf-8"))
private_key = runtime["xray"]["private_key"]
public_key = node["xray_public_key"]
for value in (private_key, public_key):
    if len(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))) != 32:
        raise SystemExit(1)
if runtime["xray"]["target"] != node["target"]:
    raise SystemExit(1)
if runtime["xray"]["server_name"] != node["server_name"]:
    raise SystemExit(1)
if re.fullmatch(r"[0-9a-f]{16}", runtime["xray"]["short_id"]) is None:
    raise SystemExit(1)
PY
}

_remove_material_temporary() {
  local temporary="$1"
  local runtime_root="$2"
  case "$temporary" in
    "$runtime_root"/.runtime-material.*) rm -rf -- "$temporary" ;;
    *) warn "Временный каталог конфигурации оставлен для безопасной проверки." ;;
  esac
}

configure_runtime_material() {
  local targets_path="$1"
  local image="$2"
  local runtime_root material_root
  runtime_root="$(_configure_path /var/lib/ezopenpn/runtime)"
  material_root="${runtime_root}/material"
  if [[ -e "$material_root" ]]; then
    if ! _validate_runtime_material "$material_root"; then
      die 45 "E_RUNTIME_MATERIAL: сохранённая конфигурация повреждена"
      return
    fi
    return 0
  fi

  select_reality_target "$targets_path" "$image" || return
  local temporary key_output
  temporary="$(mktemp -d "${runtime_root}/.runtime-material.XXXXXX")"
  key_output="${temporary}/x25519.out"
  chmod 0700 "$temporary"
  if ! _run_xray "$image" x25519 >"$key_output" 2>/dev/null; then
    _remove_material_temporary "$temporary" "$runtime_root"
    die 45 "E_RUNTIME_KEY: не удалось создать ключ узла"
    return
  fi
  chmod 0600 "$key_output"

  local master_path api_path obfs_path
  master_path="$(_configure_path /var/lib/ezopenpn/secrets/master.key)"
  api_path="$(_configure_path /var/lib/ezopenpn/secrets/hysteria-api.key)"
  obfs_path="$(_configure_path /var/lib/ezopenpn/secrets/hysteria-obfs.key)"
  if ! python3 - \
    "$temporary" "$key_output" "$REALITY_TARGET" "$REALITY_SERVER_NAME" \
    "$master_path" "$api_path" "$obfs_path" <<'PY'
from __future__ import annotations

import base64
import json
import os
import re
import secrets
import stat
import sys
from pathlib import Path

root = Path(sys.argv[1])
key_output = Path(sys.argv[2]).read_text(encoding="ascii")
target = sys.argv[3]
server_name = sys.argv[4]
secret_paths = [Path(value) for value in sys.argv[5:8]]


def parse_key(label: str) -> str:
    match = re.search(rf"^{re.escape(label)}:\s*([A-Za-z0-9_-]{{42,44}})$", key_output, re.M)
    if match is None:
        raise SystemExit(1)
    value = match.group(1)
    if len(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))) != 32:
        raise SystemExit(1)
    return value


def read_secret(path: Path) -> bytes:
    status = path.lstat()
    if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
        raise SystemExit(1)
    if stat.S_IMODE(status.st_mode) != 0o600:
        raise SystemExit(1)
    value = path.read_bytes()
    if len(value) != 32:
        raise SystemExit(1)
    return value


def encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def fallback_limits() -> dict[str, int]:
    mebibyte = 1_048_576
    kibibyte = 1_024
    rate = secrets.choice(range(256 * kibibyte, 2 * mebibyte + 1, 64 * kibibyte))
    maximum_burst = min(16 * mebibyte, rate * 4)
    burst = secrets.choice(range(rate, maximum_burst + 1, 64 * kibibyte))
    return {
        "after_bytes": secrets.choice(range(4 * mebibyte, 32 * mebibyte + 1, mebibyte)),
        "bytes_per_second": rate,
        "burst_bytes_per_second": burst,
    }


private_key = parse_key("PrivateKey")
public_key = parse_key("Password (PublicKey)")
api_secret = read_secret(secret_paths[1])
obfs_secret = read_secret(secret_paths[2])
read_secret(secret_paths[0])
upload = fallback_limits()
download = fallback_limits()
while download == upload:
    download = fallback_limits()
short_id = secrets.token_hex(8)
xhttp_path = "/" + encode(secrets.token_bytes(18))
runtime = {
    "xray": {
        "target": target,
        "server_name": server_name,
        "private_key": private_key,
        "short_id": short_id,
        "xhttp_path": xhttp_path,
        "fallback_upload": upload,
        "fallback_download": download,
    },
    "hysteria": {
        "certificate_path": "/certs/fullchain.pem",
        "private_key_path": "/certs/privkey.pem",
        "obfs_password": encode(obfs_secret),
        "stats_secret": encode(api_secret),
    },
}
node = {
    "server_name": server_name,
    "target": target,
    "xhttp_path": xhttp_path,
    "xray_public_key": public_key,
    "xray_short_id": short_id,
}
for name, payload in (("runtime-values.json", runtime), ("node.json", node)):
    path = root / name
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(payload, stream, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
directory = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(directory)
finally:
    os.close(directory)
PY
  then
    _remove_material_temporary "$temporary" "$runtime_root"
    die 45 "E_RUNTIME_MATERIAL: не удалось собрать конфигурацию"
    return
  fi
  rm -f -- "$key_output"
  _configure_chown root:root "$temporary"
  _configure_chown root:root "${temporary}/runtime-values.json"
  _configure_chown root:root "${temporary}/node.json"
  if ! mv -- "$temporary" "$material_root"; then
    _remove_material_temporary "$temporary" "$runtime_root"
    die 45 "E_RUNTIME_MATERIAL: не удалось сохранить конфигурацию"
    return
  fi
  sync -f "$runtime_root" 2>/dev/null || true
  _validate_runtime_material "$material_root" || {
    die 45 "E_RUNTIME_MATERIAL: проверка конфигурации не пройдена"
    return
  }
}

render_server_configuration() {
  local public_ip="$1"
  local release_root="$2"
  require_absolute_safe_path "$release_root" || return
  if [[ ! -d "$release_root" || -L "$release_root" || \
    ! -f "${release_root}/installer/render_config.py" ]]; then
    die 45 "E_RENDER_SOURCE: файлы выпуска недоступны"
    return
  fi

  local etc_root runtime_root material_root
  etc_root="$(_configure_path /etc/ezopenpn)"
  runtime_root="$(_configure_path /var/lib/ezopenpn/runtime)"
  material_root="${runtime_root}/material"
  if ! _validate_runtime_material "$material_root"; then
    die 45 "E_RUNTIME_MATERIAL: сохранённая конфигурация повреждена"
    return
  fi
  if ! python3 "${release_root}/installer/render_config.py" \
    --values "${material_root}/runtime-values.json" \
    --node "${material_root}/node.json" \
    --public-ip "$public_ip" \
    --deploy-root "${release_root}/deploy" \
    --etc-root "$etc_root" \
    --runtime-root "$runtime_root"; then
    die 45 "E_RENDER_CONFIG: конфигурация не прошла проверку"
    return
  fi

  _configure_chown root:10001 "${etc_root}/control.toml"
  _configure_chown root:10004 "${etc_root}/Caddyfile"
  _configure_chown root:root "${etc_root}/compose.yaml"
  _configure_chown 10002:11001 "${runtime_root}/xray/config.json"
  _configure_chown 10003:11003 "${runtime_root}/hysteria/config.yaml"
}
