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
if [[ "${1:-} ${2:-}" == "tls ping" ]]; then
  if [[ "$3" == "good.example:443" ]]; then
    printf '%s\n' \
      'Pinging without SNI' \
      'Handshake succeeded' \
      'TLS Version: TLS 1.3' \
      'Pinging with SNI' \
      'Handshake succeeded' \
      'TLS Version: TLS 1.3' \
      'TLS ping finished'
  else
    printf '%s\n' \
      'Pinging without SNI' \
      'Handshake succeeded' \
      'TLS Version: TLS 1.2' \
      'Pinging with SNI' \
      'Handshake failure'
  fi
elif [[ "$1" == "x25519" ]]; then
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

@test "runtime material selects a TLS 1.3 target and remains stable" {
  local targets="${BATS_TEST_TMPDIR}/targets.txt"
  printf '%s\n' '# candidates' bad.example good.example >"$targets"
  configure_layout

  configure_runtime_material "$targets" "$TEST_XRAY_IMAGE"

  local material="$TEST_ROOT/var/lib/ezopenpn/runtime/material"
  python3 - "$material/runtime-values.json" "$material/node.json" <<'PY'
import base64
import json
import re
import sys

runtime = json.load(open(sys.argv[1], encoding="utf-8"))
node = json.load(open(sys.argv[2], encoding="utf-8"))
assert runtime["xray"]["target"] == "good.example:443"
assert runtime["xray"]["server_name"] == "good.example"
assert runtime["xray"]["private_key"] == "UG2LfxKeyggwo4VTtVe2jycx85N1csWWomkiPdqE-nc"
assert node["xray_public_key"] == "wE2G6oGHFl38mixvBv_JGbju412yeuIyc140lRKiGGM"
assert re.fullmatch(r"[0-9a-f]{16}", runtime["xray"]["short_id"])
assert re.fullmatch(r"/[A-Za-z0-9_-]{24}", runtime["xray"]["xhttp_path"])
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
  configure_runtime_material "$targets" "$TEST_XRAY_IMAGE"
  [ "$(file_hash "$material/runtime-values.json")" = "$before" ]
}

@test "runtime material fails closed when no target passes" {
  local targets="${BATS_TEST_TMPDIR}/targets.txt"
  printf '%s\n' bad.example >"$targets"
  configure_layout

  run configure_runtime_material "$targets" "$TEST_XRAY_IMAGE"

  [ "$status" -eq 44 ]
  [[ "$output" == *"E_TARGET_UNAVAILABLE"* ]]
  [ ! -e "$TEST_ROOT/var/lib/ezopenpn/runtime/material" ]
}

@test "rendered server files contain selected values without template markers" {
  local targets="${BATS_TEST_TMPDIR}/targets.txt"
  printf '%s\n' good.example >"$targets"
  configure_layout
  configure_runtime_material "$targets" "$TEST_XRAY_IMAGE"

  render_server_configuration 203.0.113.10 "$REPOSITORY_ROOT"

  python3 - \
    "$TEST_ROOT/etc/ezopenpn/control.toml" \
    "$TEST_ROOT/var/lib/ezopenpn/runtime/xray/config.json" \
    "$TEST_ROOT/var/lib/ezopenpn/runtime/hysteria/config.yaml" <<'PY'
import json
import sys

control = open(sys.argv[1], encoding="utf-8").read()
xray = json.load(open(sys.argv[2], encoding="utf-8"))
hysteria = open(sys.argv[3], encoding="utf-8").read()
assert 'public_ip = "203.0.113.10"' in control
assert 'reality_server_name = "good.example"' in control
assert 'reality_public_key = "wE2G6oGHFl38mixvBv_JGbju412yeuIyc140lRKiGGM"' in control
assert xray["inbounds"][0]["streamSettings"]["realitySettings"]["target"] == "good.example:443"
assert "{{" not in control + hysteria
assert "/certs/fullchain.pem" in hysteria
PY
  [ "$(file_mode "$TEST_ROOT/etc/ezopenpn/control.toml")" = 0640 ]
  [ "$(file_mode "$TEST_ROOT/var/lib/ezopenpn/runtime/xray/config.json")" = 0600 ]
  cmp "$REPOSITORY_ROOT/deploy/caddy/Caddyfile" "$TEST_ROOT/etc/ezopenpn/Caddyfile"
  cmp "$REPOSITORY_ROOT/deploy/compose.yaml" "$TEST_ROOT/etc/ezopenpn/compose.yaml"
  if [[ -n "${REAL_XRAY_BIN:-}" ]]; then
    "$REAL_XRAY_BIN" run -test -config \
      "$TEST_ROOT/var/lib/ezopenpn/runtime/xray/config.json"
  fi
}
