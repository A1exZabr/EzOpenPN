#!/usr/bin/env bats

load "helpers/load.bash"

setup() {
  prepare_shell_test
  export FIXTURE_SERVER="${BATS_TEST_TMPDIR}/release"
  export EZOPENPN_RELEASE_BASE_URL="file://${FIXTURE_SERVER}"
  export EZOPENPN_EXPECTED_VERSION=v0.1.0
  export EZOPENPN_TEST_EXECUTED_PATH="${BATS_TEST_TMPDIR}/executed"
  export EZOPENPN_COSIGN_BIN="${BATS_TEST_TMPDIR}/cosign"
  source "${REPOSITORY_ROOT}/installer/lib/release.sh"
  prepare_signed_fixture \
    "https://github.com/A1exZabr/EzOpenPN/.github/workflows/release.yml@refs/tags/v0.1.0"
}

file_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

prepare_signed_fixture() {
  local identity="$1"
  local bundle_root="${BATS_TEST_TMPDIR}/bundle"
  mkdir -p "$FIXTURE_SERVER" "${bundle_root}/installer"
  printf '%s\n' '{"version":"v0.1.0"}' >"${bundle_root}/manifest.json"
  printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    'printf "%s\n" executed >"$EZOPENPN_TEST_EXECUTED_PATH"' \
    >"${bundle_root}/installer/installer-main.sh"
  chmod 0755 "${bundle_root}/installer/installer-main.sh"
  tar -czf "${FIXTURE_SERVER}/ezopenpn-bundle.tar.gz" -C "$bundle_root" .
  printf '%s  %s\n' \
    "$(file_sha256 "${FIXTURE_SERVER}/ezopenpn-bundle.tar.gz")" \
    ezopenpn-bundle.tar.gz >"${FIXTURE_SERVER}/SHA256SUMS"
  python3 - "$identity" "${FIXTURE_SERVER}/ezopenpn-bundle.sigstore.json" <<'PY'
import json
import sys

with open(sys.argv[2], "w", encoding="utf-8") as stream:
    json.dump(
        {
            "identity": sys.argv[1],
            "issuer": "https://token.actions.githubusercontent.com",
            "rekor": True,
        },
        stream,
    )
PY
  printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    'artifact=""; bundle=""; identity=""; issuer=""' \
    'while [[ $# -gt 0 ]]; do' \
    '  case "$1" in' \
    '    verify-blob) shift ;;' \
    '    --bundle) bundle="$2"; shift 2 ;;' \
    '    --certificate-identity) identity="$2"; shift 2 ;;' \
    '    --certificate-oidc-issuer) issuer="$2"; shift 2 ;;' \
    '    --*) shift ;;' \
    '    *) artifact="$1"; shift ;;' \
    '  esac' \
    'done' \
    'python3 - "$artifact" "$bundle" "$identity" "$issuer" <<"PY"' \
    'import json, pathlib, sys' \
    'assert pathlib.Path(sys.argv[1]).is_file()' \
    'data = json.loads(pathlib.Path(sys.argv[2]).read_text())' \
    'assert data == {"identity": sys.argv[3], "issuer": sys.argv[4], "rekor": True}' \
    'PY' \
    >"${EZOPENPN_COSIGN_BIN}"
  chmod 0755 "${EZOPENPN_COSIGN_BIN}"
}

prepare_rich_manifest_fixture() {
  prepare_signed_fixture \
    "https://github.com/A1exZabr/EzOpenPN/.github/workflows/release.yml@refs/tags/v0.1.0"
  local bundle_root="${BATS_TEST_TMPDIR}/bundle"
  printf '%s\n' \
    '{"version":"v0.1.0","source_commit":"0123456789012345678901234567890123456789","images":{}}' \
    >"${bundle_root}/manifest.json"
  tar -czf "${FIXTURE_SERVER}/ezopenpn-bundle.tar.gz" -C "$bundle_root" .
  printf '%s  %s\n' \
    "$(file_sha256 "${FIXTURE_SERVER}/ezopenpn-bundle.tar.gz")" \
    ezopenpn-bundle.tar.gz >"${FIXTURE_SERVER}/SHA256SUMS"
}

@test "valid release bundle executes exactly once" {
  run bootstrap_release

  [ "$status" -eq 0 ]
  [ "$(wc -l <"${EZOPENPN_TEST_EXECUTED_PATH}")" -eq 1 ]
  [[ "${lines[0]}" == *"отдельный чистый VPS"* ]]
}

@test "verified bootstrap forwards laboratory file options without evaluation" {
  local bundle_root="${BATS_TEST_TMPDIR}/bundle"
  printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    'printf "%s\n" "$@" >"$EZOPENPN_TEST_EXECUTED_PATH"' \
    >"${bundle_root}/installer/installer-main.sh"
  chmod 0755 "${bundle_root}/installer/installer-main.sh"
  tar -czf "${FIXTURE_SERVER}/ezopenpn-bundle.tar.gz" -C "$bundle_root" .
  printf '%s  %s\n' \
    "$(file_sha256 "${FIXTURE_SERVER}/ezopenpn-bundle.tar.gz")" \
    ezopenpn-bundle.tar.gz >"${FIXTURE_SERVER}/SHA256SUMS"

  run bootstrap_release \
    --advanced-lab-certificate '/tmp/certificate file.pem' \
    --advanced-lab-key '/tmp/key file.pem'

  [ "$status" -eq 0 ]
  [ "$(cat "$EZOPENPN_TEST_EXECUTED_PATH")" = $'--advanced-lab-certificate\n/tmp/certificate file.pem\n--advanced-lab-key\n/tmp/key file.pem' ]
}

@test "modified bundle is rejected before execution" {
  printf '%s' tamper >>"${FIXTURE_SERVER}/ezopenpn-bundle.tar.gz"

  run bootstrap_release

  [ "$status" -eq 31 ]
  [[ "$output" == *"E_RELEASE_VERIFY"* ]]
  [ ! -e "${EZOPENPN_TEST_EXECUTED_PATH}" ]
}

@test "wrong workflow identity is rejected" {
  prepare_signed_fixture \
    "https://github.com/example/other/.github/workflows/release.yml@refs/tags/v0.1.0"

  run bootstrap_release

  [ "$status" -eq 31 ]
  [[ "$output" == *"E_RELEASE_VERIFY"* ]]
  [ ! -e "${EZOPENPN_TEST_EXECUTED_PATH}" ]
}

@test "candidate workflow identity is accepted for a testable signed bundle" {
  prepare_signed_fixture \
    "https://github.com/A1exZabr/EzOpenPN/.github/workflows/candidate-release.yml@refs/tags/v0.1.0"

  run bootstrap_release

  [ "$status" -eq 0 ]
  [ "$(wc -l <"${EZOPENPN_TEST_EXECUTED_PATH}")" -eq 1 ]
}

@test "manifest version must equal the immutable release tag" {
  local changed="${BATS_TEST_TMPDIR}/changed"
  mkdir -p "${changed}/installer"
  printf '%s\n' '{"version":"v0.2.0"}' >"${changed}/manifest.json"
  cp "${BATS_TEST_TMPDIR}/bundle/installer/installer-main.sh" "${changed}/installer/"
  tar -czf "${FIXTURE_SERVER}/ezopenpn-bundle.tar.gz" -C "$changed" .
  printf '%s  %s\n' \
    "$(file_sha256 "${FIXTURE_SERVER}/ezopenpn-bundle.tar.gz")" \
    ezopenpn-bundle.tar.gz >"${FIXTURE_SERVER}/SHA256SUMS"

  run bootstrap_release

  [ "$status" -eq 31 ]
  [[ "$output" == *"E_RELEASE_VERIFY"* ]]
  [ ! -e "${EZOPENPN_TEST_EXECUTED_PATH}" ]
}

@test "missing verification material never executes the bundle" {
  rm "${FIXTURE_SERVER}/ezopenpn-bundle.sigstore.json"

  run bootstrap_release

  [ "$status" -eq 31 ]
  [ ! -e "${EZOPENPN_TEST_EXECUTED_PATH}" ]
}

@test "signed release accepts metadata beside the exact version" {
  prepare_rich_manifest_fixture

  run bootstrap_release

  [ "$status" -eq 0 ]
  [ "$(wc -l <"${EZOPENPN_TEST_EXECUTED_PATH}")" -eq 1 ]
}

@test "production release discovery uses the public Forgejo distribution endpoint" {
  unset EZOPENPN_RELEASE_BASE_URL EZOPENPN_EXPECTED_VERSION
  local fake_bin="${BATS_TEST_TMPDIR}/fake-bin"
  local curl_arguments="${BATS_TEST_TMPDIR}/curl-arguments"
  mkdir -p "$fake_bin"
  printf '%s\n' \
    '#!/usr/bin/env bash' \
    'printf "%s\n" "$@" >"$EZOPENPN_TEST_CURL_ARGUMENTS"' \
    'printf "%s\n" v0.1.0' \
    >"${fake_bin}/curl"
  chmod 0755 "${fake_bin}/curl"

  run env \
    PATH="${fake_bin}:${PATH}" \
    EZOPENPN_TEST_CURL_ARGUMENTS="$curl_arguments" \
    bash -c \
      'source "$1/installer/lib/release.sh"; version="$(_resolve_release_version)"; printf "%s|%s\n" "$version" "$(_release_base_url "$version")"' \
      _ "$REPOSITORY_ROOT"

  [ "$status" -eq 0 ]
  [ "$output" = "v0.1.0|https://git.alexzabrodin.pro/ezopenpn/releases/download/v0.1.0" ]
  grep -Fxq \
    'https://git.alexzabrodin.pro/ezopenpn/releases/latest/version' \
    "$curl_arguments"
}
