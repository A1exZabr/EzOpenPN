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
  export TEST_DOCTOR_CAMOUFLAGE=1
  export TEST_DOCTOR_REDIRECT=1
  export TEST_DOCTOR_PORTS=1
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
  [[ "$output" == *"camouflage: ok"* ]]
  [[ "$output" == *"http_redirect: ok"* ]]
  [[ "$output" == *"published_ports: ok"* ]]
}

@test "doctor flags a stub that lost its camouflage" {
  export TEST_DOCTOR_CAMOUFLAGE=0

  run_cli doctor

  [ "$status" -eq 1 ]
  [[ "$output" == *"camouflage: failed"* ]]
}

@test "camouflage check needs TLS 1.3 and TLS 1.2 with HSTS and no server name" {
  source "${REPOSITORY_ROOT}/installer/lib/common.sh"
  source "${REPOSITORY_ROOT}/installer/lib/state.sh"
  source "${REPOSITORY_ROOT}/installer/lib/diagnostics.sh"
  local fake_bin="${BATS_TEST_TMPDIR}/bin"
  mkdir -p "$fake_bin"
  cat >"$fake_bin/curl" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$CURL_LOG"
printf 'HTTP/2 200\r\nstrict-transport-security: max-age=31536000\r\n%s\r\n' "${EXTRA_HEADER:-}"
SH
  chmod 0755 "$fake_bin/curl"
  export CURL_LOG="${BATS_TEST_TMPDIR}/curl.log"
  PATH="$fake_bin:$PATH"

  _doctor_camouflage
  grep -Fq -- '--tlsv1.3 --tls-max 1.3 https://203.0.113.10/' "$CURL_LOG"
  grep -Fq -- '--tlsv1.2 --tls-max 1.2 https://203.0.113.10/' "$CURL_LOG"

  EXTRA_HEADER='server: Caddy'
  export EXTRA_HEADER
  run _doctor_camouflage
  [ "$status" -ne 0 ]
}

@test "redirect check accepts only a permanent redirect to the stub" {
  source "${REPOSITORY_ROOT}/installer/lib/common.sh"
  source "${REPOSITORY_ROOT}/installer/lib/state.sh"
  source "${REPOSITORY_ROOT}/installer/lib/diagnostics.sh"
  local fake_bin="${BATS_TEST_TMPDIR}/bin"
  mkdir -p "$fake_bin"
  cat >"$fake_bin/curl" <<'SH'
#!/usr/bin/env bash
printf 'HTTP/1.1 %s\r\nLocation: https://203.0.113.10/\r\n' "$REDIRECT_STATUS"
SH
  chmod 0755 "$fake_bin/curl"
  PATH="$fake_bin:$PATH"

  REDIRECT_STATUS='301 Moved Permanently'
  export REDIRECT_STATUS
  _doctor_http_redirect

  REDIRECT_STATUS='308 Permanent Redirect'
  run _doctor_http_redirect
  [ "$status" -ne 0 ]
}

@test "published ports allow only the four public bindings" {
  source "${REPOSITORY_ROOT}/installer/lib/common.sh"
  source "${REPOSITORY_ROOT}/installer/lib/state.sh"
  source "${REPOSITORY_ROOT}/installer/lib/diagnostics.sh"
  _diagnostic_compose() {
    printf '%s\n' \
      '{"Service":"xray","Publishers":[{"URL":"203.0.113.10","TargetPort":8443,"PublishedPort":443,"Protocol":"tcp"},{"URL":"","TargetPort":10085,"PublishedPort":0,"Protocol":"tcp"}]}' \
      '{"Service":"hysteria","Publishers":[{"URL":"203.0.113.10","TargetPort":8443,"PublishedPort":443,"Protocol":"udp"}]}' \
      '{"Service":"gateway","Publishers":[{"URL":"203.0.113.10","TargetPort":8080,"PublishedPort":80,"Protocol":"tcp"},{"URL":"203.0.113.10","TargetPort":9443,"PublishedPort":9443,"Protocol":"tcp"}]}' \
      "${EXTRA_SERVICE:-}"
  }

  _doctor_published_ports

  EXTRA_SERVICE='{"Service":"control","Publishers":[{"URL":"0.0.0.0","TargetPort":8000,"PublishedPort":8000,"Protocol":"tcp"}]}'
  run _doctor_published_ports
  [ "$status" -ne 0 ]
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
