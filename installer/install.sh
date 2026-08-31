#!/usr/bin/env bash

set +x
set -Eeuo pipefail
umask 077

readonly EZOPENPN_COSIGN_VERSION="v3.1.2"
readonly EZOPENPN_COSIGN_SHA256="f7622ed3cf22e55e1ae6377c080979ff77a22da9981c11df222a2e444991e7cf"
readonly EZOPENPN_COSIGN_URL="https://github.com/sigstore/cosign/releases/download/v3.1.2/cosign-linux-amd64"
readonly EZOPENPN_OIDC_ISSUER="https://token.actions.githubusercontent.com"

_release_test_mode() {
  [[ -n "${EZOPENPN_RELEASE_BASE_URL:-}" && -n "${EZOPENPN_EXPECTED_VERSION:-}" ]]
}

_release_error() {
  printf '[EzOpenPN] E_RELEASE_VERIFY: %s\n' "$1" >&2
  return 31
}

_valid_release_tag() {
  [[ "$1" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

_resolve_release_version() {
  if _release_test_mode; then
    if ! _valid_release_tag "$EZOPENPN_EXPECTED_VERSION"; then
      _release_error "тестовая версия имеет неверный формат"
      return
    fi
    printf '%s\n' "$EZOPENPN_EXPECTED_VERSION"
    return
  fi
  if [[ -n "${EZOPENPN_RELEASE_BASE_URL:-}" || -n "${EZOPENPN_EXPECTED_VERSION:-}" ]]; then
    _release_error "тестовые параметры можно использовать только вместе"
    return
  fi

  local effective_url version
  effective_url="$(curl --proto '=https' --tlsv1.2 -fsSL \
    --connect-timeout 10 --max-time 30 -o /dev/null -w '%{url_effective}' \
    https://github.com/A1exZabr/EzOpenPN/releases/latest)" || {
      _release_error "не удалось определить текущую стабильную версию"
      return
    }
  version="${effective_url##*/tag/}"
  if [[ "$version" == "$effective_url" || ! "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    _release_error "GitHub вернул неверную версию"
    return
  fi
  printf '%s\n' "$version"
}

_release_base_url() {
  local version="$1"
  if _release_test_mode; then
    printf '%s\n' "${EZOPENPN_RELEASE_BASE_URL%/}"
  else
    printf 'https://github.com/A1exZabr/EzOpenPN/releases/download/%s\n' "$version"
  fi
}

_download_release_asset() {
  local base_url="$1"
  local asset="$2"
  local destination="$3"
  if [[ "$base_url" == file://* ]] && _release_test_mode; then
    cp "${base_url#file://}/${asset}" "$destination"
    return
  fi
  [[ "$base_url" == https://* ]] || return 1
  curl --proto '=https' --tlsv1.2 -fsSL --connect-timeout 10 --max-time 120 \
    "${base_url}/${asset}" -o "$destination"
}

_sha256_file() {
  python3 - "$1" <<'PY'
from __future__ import annotations

import hashlib
import sys

digest = hashlib.sha256()
with open(sys.argv[1], "rb") as stream:
    while block := stream.read(1024 * 1024):
        digest.update(block)
print(digest.hexdigest())
PY
}

_prepare_cosign() {
  local bootstrap_root="$1"
  if _release_test_mode && [[ -n "${EZOPENPN_COSIGN_BIN:-}" ]]; then
    [[ -x "$EZOPENPN_COSIGN_BIN" ]] || return 1
    printf '%s\n' "$EZOPENPN_COSIGN_BIN"
    return
  fi

  local destination="${bootstrap_root}/cosign-${EZOPENPN_COSIGN_VERSION}"
  curl --proto '=https' --tlsv1.2 -fsSL --connect-timeout 10 --max-time 180 \
    "$EZOPENPN_COSIGN_URL" -o "$destination" || return 1
  [[ "$(_sha256_file "$destination")" == "$EZOPENPN_COSIGN_SHA256" ]] || return 1
  chmod 0700 "$destination"
  printf '%s\n' "$destination"
}

_verify_checksum_and_archive() {
  local release_root="$1"
  local version="$2"
  python3 - "$release_root" "$version" <<'PY'
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import sys
import tarfile

root = pathlib.Path(sys.argv[1])
version = sys.argv[2]
archive = root / "ezopenpn-bundle.tar.gz"
checksum_line = (root / "SHA256SUMS").read_text(encoding="ascii").strip()
match = re.fullmatch(r"([0-9a-f]{64})  ezopenpn-bundle\.tar\.gz", checksum_line)
if match is None:
    raise SystemExit(1)
digest = hashlib.sha256(archive.read_bytes()).hexdigest()
if digest != match.group(1):
    raise SystemExit(1)

with tarfile.open(archive, "r:gz") as bundle:
    members = bundle.getmembers()
    for member in members:
        path = pathlib.PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts or member.issym() or member.islnk():
            raise SystemExit(1)
        if not (member.isdir() or member.isfile()):
            raise SystemExit(1)
    manifests = [member for member in members if member.name.lstrip("./") == "manifest.json"]
    if len(manifests) != 1:
        raise SystemExit(1)
    stream = bundle.extractfile(manifests[0])
    if stream is None:
        raise SystemExit(1)
    manifest = json.load(stream)
if not isinstance(manifest, dict) or manifest.get("version") != version:
    raise SystemExit(1)
PY
}

verify_release_bundle() {
  local release_root="$1"
  local version="$2"
  local cosign_bin="$3"
  local archive="${release_root}/ezopenpn-bundle.tar.gz"
  local sigstore_bundle="${release_root}/ezopenpn-bundle.sigstore.json"
  [[ -f "$archive" && -f "${release_root}/SHA256SUMS" && \
    -f "$sigstore_bundle" ]] || return 1
  _verify_checksum_and_archive "$release_root" "$version" || return 1

  local identity
  identity="https://github.com/A1exZabr/EzOpenPN/.github/workflows/release.yml@refs/tags/${version}"
  "$cosign_bin" verify-blob "$archive" \
    --bundle "$sigstore_bundle" \
    --certificate-identity "$identity" \
    --certificate-oidc-issuer "$EZOPENPN_OIDC_ISSUER" \
    >/dev/null 2>&1
}

_cleanup_bootstrap() {
  local bootstrap_root="$1"
  case "$bootstrap_root" in
    /tmp/ezopenpn-bootstrap.* | "${TMPDIR:-/tmp}"/ezopenpn-bootstrap.*)
      rm -rf -- "$bootstrap_root"
      ;;
    *)
      printf '[EzOpenPN] отказ от очистки неожиданного временного пути\n' >&2
      ;;
  esac
}

bootstrap_release() (
  printf '%s\n' \
    "Первая рекомендация: используйте отдельный чистый VPS без сайтов и других сервисов."
  if ! _release_test_mode && [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    printf '[EzOpenPN] E_PREFLIGHT_ROOT: запустите команду через sudo\n' >&2
    return 20
  fi

  local version
  version="$(_resolve_release_version)" || return $?
  local temporary_parent="/tmp"
  if _release_test_mode; then
    temporary_parent="${TMPDIR:-/tmp}"
  fi
  local bootstrap_root
  bootstrap_root="$(mktemp -d "${temporary_parent}/ezopenpn-bootstrap.XXXXXX")"
  trap '_cleanup_bootstrap "$bootstrap_root"' EXIT HUP INT TERM

  local base_url
  base_url="$(_release_base_url "$version")"
  local asset
  for asset in \
    ezopenpn-bundle.tar.gz \
    SHA256SUMS \
    ezopenpn-bundle.sigstore.json; do
    if ! _download_release_asset "$base_url" "$asset" "${bootstrap_root}/${asset}"; then
      _release_error "не удалось скачать полный набор release-файлов"
      return
    fi
  done

  local cosign_bin
  if ! cosign_bin="$(_prepare_cosign "$bootstrap_root")"; then
    _release_error "не удалось проверить инструмент подписи"
    return
  fi
  if ! verify_release_bundle "$bootstrap_root" "$version" "$cosign_bin"; then
    _release_error "подпись, checksum или manifest не прошли проверку"
    return
  fi

  local extracted="${bootstrap_root}/bundle"
  mkdir -p "$extracted"
  tar -xzf "${bootstrap_root}/ezopenpn-bundle.tar.gz" -C "$extracted"
  local installer_main="${extracted}/installer/installer-main.sh"
  [[ -f "$installer_main" && ! -L "$installer_main" ]] || {
    _release_error "в проверенном пакете нет установщика"
    return
  }

  if _release_test_mode; then
    env -i \
      PATH="/usr/sbin:/usr/bin:/sbin:/bin" \
      HOME="${HOME:-/root}" \
      LANG=C.UTF-8 \
      EZOPENPN_BUNDLE_ROOT="$extracted" \
      EZOPENPN_TEST_EXECUTED_PATH="${EZOPENPN_TEST_EXECUTED_PATH:-}" \
      bash --noprofile --norc "$installer_main" "$@"
  else
    env -i \
      PATH="/usr/sbin:/usr/bin:/sbin:/bin" \
      HOME=/root \
      LANG=C.UTF-8 \
      EZOPENPN_BUNDLE_ROOT="$extracted" \
      bash --noprofile --norc "$installer_main" "$@"
  fi
)

if [[ -z "${BASH_SOURCE[0]:-}" || "${BASH_SOURCE[0]}" == "$0" ]]; then
  bootstrap_release "$@"
fi
