#!/usr/bin/env bats

load "helpers/load.bash"

setup() {
  prepare_shell_test
  export EZOPENPN_ROOT_PREFIX="$TEST_ROOT"
  export TEST_CHOWN_LOG="${BATS_TEST_TMPDIR}/chown.log"
  export TEST_XRAY_BIN="${BATS_TEST_TMPDIR}/xray"
  export TEST_XRAY_IMAGE="example.invalid/xray@sha256:$(printf 'a%.0s' {1..64})"
  cat >"$TEST_XRAY_BIN" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
# Only key generation is expected; external TLS probing is no longer used.
if [[ "$1" == "x25519" ]]; then
  printf '%s\n' \
    'PrivateKey: UG2LfxKeyggwo4VTtVe2jycx85N1csWWomkiPdqE-nc' \
    'Password (PublicKey): wE2G6oGHFl38mixvBv_JGbju412yeuIyc140lRKiGGM'
else
  exit 2
fi
SH
  chmod 0700 "$TEST_XRAY_BIN"
  source "${REPOSITORY_ROOT}/installer/lib/common.sh"
  source "${REPOSITORY_ROOT}/installer/lib/configure.sh"
}

file_hash() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

file_mode() {
  python3 - "$1" <<'PY'
import os
import stat
import sys

print(f"{stat.S_IMODE(os.lstat(sys.argv[1]).st_mode):04o}")
PY
}

@test "layout creates exact service directories and three 32 byte secrets" {
  configure_layout

  [ "$(wc -c <"$TEST_ROOT/var/lib/ezopenpn/secrets/master.key")" -eq 32 ]
  [ "$(wc -c <"$TEST_ROOT/var/lib/ezopenpn/secrets/hysteria-api.key")" -eq 32 ]
  [ "$(wc -c <"$TEST_ROOT/var/lib/ezopenpn/secrets/hysteria-obfs.key")" -eq 32 ]
  [ "$(file_mode "$TEST_ROOT/var/lib/ezopenpn/secrets/master.key")" = 0600 ]
  [ "$(file_mode "$TEST_ROOT/var/lib/ezopenpn/runtime/xray-run")" = 0750 ]
  [ "$(file_mode "$TEST_ROOT/var/lib/ezopenpn/runtime/hysteria-certs")" = 0750 ]
  grep -Fq "10001:10001 $TEST_ROOT/var/lib/ezopenpn/control" "$TEST_CHOWN_LOG"
  grep -Fq "10002:11001 $TEST_ROOT/var/lib/ezopenpn/runtime/xray" "$TEST_CHOWN_LOG"
  grep -Fq "10004:11003 $TEST_ROOT/var/lib/ezopenpn/caddy" "$TEST_CHOWN_LOG"
}

@test "rerun preserves every existing server secret" {
  configure_layout
  local before
  before="$(
    for path in "$TEST_ROOT"/var/lib/ezopenpn/secrets/*.key; do
      file_hash "$path"
    done
  )"

  configure_layout

  local after
  after="$(
    for path in "$TEST_ROOT"/var/lib/ezopenpn/secrets/*.key; do
      file_hash "$path"
    done
  )"
  [ "$before" = "$after" ]
}

@test "runtime material creates node keys without an external target" {
  configure_layout

  configure_runtime_material "$TEST_XRAY_IMAGE"

  local material="$TEST_ROOT/var/lib/ezopenpn/runtime/material"
  python3 - "$material/runtime-values.json" "$material/node.json" <<'PY'
import base64
import json
import re
import sys

runtime = json.load(open(sys.argv[1], encoding="utf-8"))
node = json.load(open(sys.argv[2], encoding="utf-8"))
assert set(runtime["xray"]) == {
    "private_key", "short_id", "fallback_upload", "fallback_download"
}
assert set(node) == {"xray_public_key", "xray_short_id"}
assert runtime["xray"]["private_key"] == "UG2LfxKeyggwo4VTtVe2jycx85N1csWWomkiPdqE-nc"
assert node["xray_public_key"] == "wE2G6oGHFl38mixvBv_JGbju412yeuIyc140lRKiGGM"
assert re.fullmatch(r"[0-9a-f]{16}", runtime["xray"]["short_id"])
assert node["xray_short_id"] == runtime["xray"]["short_id"]
for key in ("obfs_password", "stats_secret"):
    value = runtime["hysteria"][key]
    assert len(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))) == 32
for direction in ("fallback_upload", "fallback_download"):
    limits = runtime["xray"][direction]
    assert 1_048_576 <= limits["after_bytes"] <= 67_108_864
    assert 131_072 <= limits["bytes_per_second"] <= 8_388_608
    assert limits["bytes_per_second"] <= limits["burst_bytes_per_second"] <= 33_554_432
assert runtime["xray"]["fallback_upload"] != runtime["xray"]["fallback_download"]
PY
  local before
  before="$(file_hash "$material/runtime-values.json")"
  configure_runtime_material "$TEST_XRAY_IMAGE"
  [ "$(file_hash "$material/runtime-values.json")" = "$before" ]
}

@test "runtime material requires a digest pinned image" {
  configure_layout

  run configure_runtime_material "example.invalid/xray:latest"

  [ "$status" -eq 45 ]
  [[ "$output" == *"E_IMAGE_REFERENCE"* ]]
  [ ! -e "$TEST_ROOT/var/lib/ezopenpn/runtime/material" ]
}

@test "material from an earlier release is kept and still renders" {
  configure_layout
  local material="$TEST_ROOT/var/lib/ezopenpn/runtime/material"
  install -d -m 0700 "$material"
  python3 - "$material" <<'PY'
import base64
import json
import os
import sys
from pathlib import Path

root = Path(sys.argv[1])
legacy = {
    "target": "www.example.org:443",
    "server_name": "www.example.org",
    "xhttp_path": "/abcdefghijklmnopqrstuvwx",
}
limits = {
    "fallback_upload": {
        "after_bytes": 9437184, "bytes_per_second": 786432, "burst_bytes_per_second": 3145728
    },
    "fallback_download": {
        "after_bytes": 11534336, "bytes_per_second": 1048576, "burst_bytes_per_second": 4194304
    },
}


def secret(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


runtime = {
    "xray": {
        "private_key": "UG2LfxKeyggwo4VTtVe2jycx85N1csWWomkiPdqE-nc",
        "short_id": "a1b2c3d4e5f60708",
        **legacy,
        **limits,
    },
    "hysteria": {
        "certificate_path": "/certs/fullchain.pem",
        "private_key_path": "/certs/privkey.pem",
        "obfs_password": secret(b"o" * 32),
        "stats_secret": secret(b"s" * 32),
    },
}
node = {
    "xray_public_key": "wE2G6oGHFl38mixvBv_JGbju412yeuIyc140lRKiGGM",
    "xray_short_id": "a1b2c3d4e5f60708",
    **legacy,
}
for name, payload in (("runtime-values.json", runtime), ("node.json", node)):
    path = root / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    os.chmod(path, 0o600)
PY
  local before
  before="$(file_hash "$material/runtime-values.json")"

  configure_runtime_material "$TEST_XRAY_IMAGE"
  render_server_configuration 203.0.113.10 "$REPOSITORY_ROOT"

  [ "$(file_hash "$material/runtime-values.json")" = "$before" ]
  python3 - "$TEST_ROOT/var/lib/ezopenpn/runtime/xray/config.json" <<'PY'
import json
import sys

reality = json.load(open(sys.argv[1], encoding="utf-8"))["inbounds"][0]["streamSettings"][
    "realitySettings"
]
assert reality["target"] == "gateway:8443"
assert reality["serverNames"] == [""]
PY
}

@test "rendered server files contain selected values without template markers" {
  configure_layout
  configure_runtime_material "$TEST_XRAY_IMAGE"

  render_server_configuration 203.0.113.10 "$REPOSITORY_ROOT"

  python3 - \
    "$TEST_ROOT/etc/ezopenpn/control.toml" \
    "$TEST_ROOT/var/lib/ezopenpn/runtime/xray/config.json" \
    "$TEST_ROOT/var/lib/ezopenpn/runtime/hysteria/config.yaml" \
    "$TEST_ROOT/etc/ezopenpn/Caddyfile" <<'PY'
import json
import sys

control = open(sys.argv[1], encoding="utf-8").read()
xray = json.load(open(sys.argv[2], encoding="utf-8"))
hysteria = open(sys.argv[3], encoding="utf-8").read()
caddyfile = open(sys.argv[4], encoding="utf-8").read()
assert 'public_ip = "203.0.113.10"' in control
assert "reality_server_name" not in control
assert "xhttp_path" not in control
assert 'reality_public_key = "wE2G6oGHFl38mixvBv_JGbju412yeuIyc140lRKiGGM"' in control
stream = xray["inbounds"][0]["streamSettings"]
assert stream["network"] == "raw"
assert stream["realitySettings"]["target"] == "gateway:8443"
assert "{{" not in control + hysteria
assert "/certs/fullchain.pem" in hysteria
assert "redir https://{host}{uri} 301" in caddyfile
assert "<title>Welcome</title>" not in caddyfile
assert "EzOpenPN" not in hysteria + caddyfile
PY
  [ "$(file_mode "$TEST_ROOT/etc/ezopenpn/control.toml")" = 0640 ]
  [ "$(file_mode "$TEST_ROOT/var/lib/ezopenpn/runtime/xray/config.json")" = 0600 ]
  grep -Fq "root:11003 $TEST_ROOT/etc/ezopenpn/Caddyfile" "$TEST_CHOWN_LOG"
  cmp "$REPOSITORY_ROOT/deploy/compose.yaml" "$TEST_ROOT/etc/ezopenpn/compose.yaml"
  if [[ -n "${REAL_XRAY_BIN:-}" ]]; then
    "$REAL_XRAY_BIN" run -test -config \
      "$TEST_ROOT/var/lib/ezopenpn/runtime/xray/config.json"
  fi
}
