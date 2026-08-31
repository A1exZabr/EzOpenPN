#!/usr/bin/env bats

load "helpers/load.bash"

setup() {
  prepare_shell_test
  export EZOPENPN_ROOT_PREFIX="$TEST_ROOT"
  export EZOPENPN_LIBRARY_ROOT="${REPOSITORY_ROOT}/installer/lib"
  export EZOPENPN_TEST_EUID=0
  mkdir -p \
    "$TEST_ROOT/etc/ezopenpn" \
    "$TEST_ROOT/var/lib/ezopenpn/secrets" \
    "$TEST_ROOT/var/lib/ezopenpn/runtime/xray"
  printf '%s\n' \
    '{"admin_login":"owner","laboratory_mode":false,"public_ipv4":"203.0.113.10","version":"v0.1.0"}' \
    >"$TEST_ROOT/var/lib/ezopenpn/install.json"
  printf '%s\n' 'services: {}' >"$TEST_ROOT/etc/ezopenpn/compose.yaml"
  : >"$TEST_ROOT/etc/ezopenpn/stack.env"
  head -c 32 /dev/zero >"$TEST_ROOT/var/lib/ezopenpn/secrets/master.key"
  head -c 32 /dev/zero >"$TEST_ROOT/var/lib/ezopenpn/secrets/hysteria-api.key"
  head -c 32 /dev/zero >"$TEST_ROOT/var/lib/ezopenpn/secrets/hysteria-obfs.key"
  chmod 0600 "$TEST_ROOT/var/lib/ezopenpn/secrets/"*.key
  printf '%s\n' \
    '{"inbounds":[{"streamSettings":{"realitySettings":{"privateKey":"runtime-private-value","shortIds":["a1b2c3d4e5f60708"]}}}]}' \
    >"$TEST_ROOT/var/lib/ezopenpn/runtime/xray/config.json"
  export TEST_HEALTH_CONTROL=healthy
  export TEST_HEALTH_XRAY=healthy
  export TEST_HEALTH_HYSTERIA=healthy
  export TEST_HEALTH_GATEWAY=healthy
  export TEST_HEALTH_CERT_SYNC=healthy
  export TEST_CERTIFICATE_EXPIRY=2030-01-02T03:04:05Z
  export TEST_ACTIVE_PROFILES=2
  export TEST_PANEL_READY=1
  export TEST_DOCTOR_PREFLIGHT=1
  export TEST_DOCTOR_PERMISSIONS=1
  export TEST_DOCTOR_COMPOSE=1
  export TEST_DOCTOR_DATABASE=1
  export TEST_DOCTOR_CERTIFICATE=1
  export TEST_DOCTOR_RECONCILE=1
  export TEST_DOCTOR_PUBLIC=1
}

run_cli() {
  run bash "${REPOSITORY_ROOT}/installer/bin/ezopenpn" "$@"
}

@test "healthy status reports version services certificate and profiles" {
  run_cli status

  [ "$status" -eq 0 ]
  [[ "$output" == *"v0.1.0"* ]]
  [[ "$output" == *"control: healthy"* ]]
  [[ "$output" == *"2030-01-02T03:04:05Z"* ]]
  [[ "$output" == *"Активных профилей: 2"* ]]
}

@test "one unhealthy service makes status degraded" {
  export TEST_HEALTH_XRAY=unhealthy

  run_cli status

  [ "$status" -eq 1 ]
  [[ "$output" == *"xray: unhealthy"* ]]
  [[ "$output" == *"Итог: есть проблемы"* ]]
}

@test "doctor reports every safe check without raw command output" {
  run_cli doctor

  [ "$status" -eq 0 ]
  [[ "$output" == *"preflight: ok"* ]]
  [[ "$output" == *"permissions: ok"* ]]
  [[ "$output" == *"public_https: ok"* ]]
}

@test "doctor returns degraded when one invariant fails" {
  export TEST_DOCTOR_DATABASE=0

  run_cli doctor

  [ "$status" -eq 1 ]
  [[ "$output" == *"database: failed"* ]]
}

@test "logs redact stored values and connection links" {
  local encoded
  encoded="$(python3 - <<'PY'
import base64
print(base64.urlsafe_b64encode(bytes(32)).rstrip(b"=").decode())
PY
)"
  export TEST_LOG_OUTPUT="normal line ${encoded} runtime-private-value vless://sensitive-link"

  run_cli logs control --since 60 --tail 20

  [ "$status" -eq 0 ]
  [[ "$output" == *"normal line"* ]]
  [[ "$output" == *"<redacted>"* ]]
  [[ "$output" != *"$encoded"* ]]
  [[ "$output" != *"runtime-private-value"* ]]
  [[ "$output" != *"sensitive-link"* ]]
}
