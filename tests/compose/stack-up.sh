#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
state_path="/tmp/ezopenpn-stack-state-$(id -u).json"
if [[ -e "$state_path" ]]; then
  echo "a stack test state already exists; run stack-down.sh first" >&2
  exit 1
fi

test_root="$(mktemp -d "${TMPDIR:-/tmp}/ezopenpn-stack.XXXXXX")"
project="$(bash "${repository_root}/tests/compose/project-name.sh" "$test_root")"
environment_path="${test_root}/stack.env"
compose=(
  docker compose
  --env-file "$environment_path"
  -f "${repository_root}/deploy/compose.yaml"
  -f "${repository_root}/tests/compose/stack-override.yaml"
  --project-name "$project"
)

cleanup_on_error() {
  if [[ -f "$environment_path" ]]; then
    "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
  fi
  sudo rm -rf -- "$test_root"
  rm -f -- "$state_path"
}
trap cleanup_on_error ERR INT TERM

bash "${repository_root}/tests/compose/fixtures/test-ip-cert.sh" \
  "${test_root}/gateway-certs" 127.0.0.1
PATH="${repository_root}/.venv/bin:${PATH}" \
  uv run python "${repository_root}/tests/compose/stack_prepare.py" \
  "$test_root" "$state_path" "$project"

sudo chown -R 10001:10001 "${test_root}/control" "${test_root}/secrets"
sudo chown root:10001 "${test_root}/control.toml"
sudo chmod 0640 "${test_root}/control.toml"
sudo chown -R 10002:11001 "${test_root}/runtime/xray" "${test_root}/xray-run"
sudo chown -R 10003:11003 "${test_root}/runtime/hysteria"
sudo chown -R 10004:11003 "${test_root}/caddy-data" "${test_root}/hysteria-certs"
sudo chown 10004:11003 "${test_root}/gateway-certs"
sudo chmod 0750 "${test_root}/gateway-certs"
sudo chown 10004:11003 \
  "${test_root}/gateway-certs/server.crt" \
  "${test_root}/gateway-certs/server.key"
sudo chmod 0640 \
  "${test_root}/gateway-certs/server.crt" \
  "${test_root}/gateway-certs/server.key"

docker build -f "${repository_root}/control/Dockerfile" \
  -t ezopenpn-control:test "$repository_root"
docker build -f "${repository_root}/runtime/Dockerfile.xray" \
  -t ezopenpn-xray:test "$repository_root"
docker build -f "${repository_root}/runtime/Dockerfile.cert-sync" \
  -t ezopenpn-cert-sync:test "$repository_root"
docker build -f "${repository_root}/runtime/Dockerfile.gateway" \
  -t ezopenpn-gateway:test "$repository_root"
"${compose[@]}" config --quiet

trap - ERR INT TERM
echo "stack harness prepared"
