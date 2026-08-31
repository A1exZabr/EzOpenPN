#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

repository_root="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
configuration="${repository_root}/tools/toolchain.toml"
lock_file="${repository_root}/tools/toolchain.lock"
mode="${1:---check}"
destination="${2:-}"
selected_tools=()
uv_binary="${UV:-uv}"

if [[ "$uv_binary" == */* ]]; then
  [[ -x "$uv_binary" ]]
else
  command -v "$uv_binary" >/dev/null
fi

case "$mode" in
  --check)
    [[ $# -eq 1 ]]
    ;;
  --install)
    [[ $# -ge 2 ]]
    if [[ $# -gt 2 ]]; then
      selected_tools=("${@:3}")
    fi
    ;;
  *)
    printf '%s\n' \
      'usage: tools/lock_toolchain.sh --check | --install ABSOLUTE_DIRECTORY [TOOL ...]' >&2
    exit 2
    ;;
esac

"$uv_binary" run python - \
  "$configuration" "$lock_file" "${repository_root}/installer/install.sh" <<'PY'
from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

configuration_path = Path(sys.argv[1])
lock_path = Path(sys.argv[2])
installer_path = Path(sys.argv[3])
configuration = tomllib.loads(configuration_path.read_text(encoding="utf-8"))
locked = tomllib.loads(lock_path.read_text(encoding="utf-8"))
required = {
    "actionlint",
    "bats",
    "cosign",
    "gitleaks",
    "govulncheck",
    "lychee",
    "reuse",
    "shellcheck",
    "syft",
    "trivy",
}
if configuration.get("schema") != 1 or locked.get("schema") != 1:
    raise SystemExit("toolchain schema is unsupported")
if configuration.get("platform") != "linux-amd64" or locked.get("platform") != "linux-amd64":
    raise SystemExit("toolchain platform is unsupported")
configured_tools = configuration.get("tools")
locked_tools = locked.get("tools")
if not isinstance(configured_tools, dict) or set(configured_tools) != required:
    raise SystemExit("toolchain configuration is incomplete")
if not isinstance(locked_tools, dict) or set(locked_tools) != required:
    raise SystemExit("toolchain lock is incomplete")
allowed_hosts = {"github.com", "files.pythonhosted.org"}
for name in sorted(required):
    configured = configured_tools[name]
    artifact = locked_tools[name]
    if artifact.get("version") != configured.get("version"):
        raise SystemExit(f"version drift for {name}")
    digest = artifact.get("sha256")
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise SystemExit(f"invalid digest for {name}")
    url = artifact.get("url")
    if not isinstance(url, str) or urlparse(url).scheme != "https":
        raise SystemExit(f"invalid URL for {name}")
    if urlparse(url).hostname not in allowed_hosts:
        raise SystemExit(f"untrusted URL for {name}")
    if configured["version"] not in url:
        raise SystemExit(f"version is absent from URL for {name}")
    if artifact.get("kind") not in {
        "bats-source",
        "file",
        "go-source",
        "python-source",
        "tar",
    }:
        raise SystemExit(f"invalid artifact kind for {name}")
    binary = artifact.get("binary")
    if not isinstance(binary, str):
        raise SystemExit(f"invalid binary path for {name}")
    binary_path = PurePosixPath(binary)
    if binary_path.is_absolute() or ".." in binary_path.parts:
        raise SystemExit(f"unsafe binary path for {name}")

installer = installer_path.read_text(encoding="utf-8")
cosign = locked_tools["cosign"]
for variable, expected in (
    ("EZOPENPN_COSIGN_VERSION", "v" + cosign["version"]),
    ("EZOPENPN_COSIGN_SHA256", cosign["sha256"]),
    ("EZOPENPN_COSIGN_URL", cosign["url"]),
):
    match = re.search(rf'^readonly {variable}="([^"]+)"$', installer, re.MULTILINE)
    if match is None or match.group(1) != expected:
        raise SystemExit(f"installer {variable} drift")
PY

if [[ "$mode" == --check ]]; then
  exit 0
fi

if [[ "$destination" != /* || "$destination" == / || -L "$destination" ]]; then
  printf '%s\n' 'tool destination must be a safe absolute directory' >&2
  exit 2
fi
case "$destination" in
  /etc | /usr | /var | /opt | "$repository_root")
    printf '%s\n' 'tool destination is too broad' >&2
    exit 2
    ;;
esac
if [[ "$(uname -s)" != Linux || ! "$(uname -m)" =~ ^(x86_64|amd64)$ ]]; then
  printf '%s\n' 'locked installation supports only Linux amd64' >&2
  exit 2
fi

install -d -m 0700 "$destination" "$destination/bin"
temporary_root="$(mktemp -d "${TMPDIR:-/tmp}/ezopenpn-toolchain.XXXXXXXX")"
trap 'case "$temporary_root" in /tmp/ezopenpn-toolchain.* | "${TMPDIR:-/tmp}"/ezopenpn-toolchain.*) rm -rf -- "$temporary_root" ;; esac' EXIT

declare -A requested_tools=()
for requested in "${selected_tools[@]}"; do
  [[ "$requested" =~ ^[a-z0-9-]+$ ]] || {
    printf 'invalid tool name: %s\n' "$requested" >&2
    exit 2
  }
  requested_tools["$requested"]=1
done

"$uv_binary" run python - "$lock_file" <<'PY' >"${temporary_root}/artifacts.tsv"
from __future__ import annotations

import sys
import tomllib
from pathlib import Path

locked = tomllib.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
for name, artifact in sorted(locked["tools"].items()):
    print(
        "\t".join(
            (
                name,
                artifact["url"],
                artifact["sha256"],
                artifact["kind"],
                artifact["binary"],
            )
        )
    )
PY

_extract_safe() {
  local archive="$1"
  local output="$2"
  "$uv_binary" run python - "$archive" "$output" <<'PY'
from __future__ import annotations

import sys
import tarfile
from pathlib import Path, PurePosixPath

archive = Path(sys.argv[1])
output = Path(sys.argv[2])
output.mkdir(mode=0o700)
with tarfile.open(archive, "r:*") as source:
    members = source.getmembers()
    for member in members:
        path = PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts:
            raise SystemExit("unsafe archive path")
        if not (member.isdir() or member.isfile()):
            raise SystemExit("unsafe archive member")
    source.extractall(output, members=members, filter="data")
PY
}

while IFS=$'\t' read -r name url expected kind binary; do
  if (( ${#requested_tools[@]} > 0 )) && \
    [[ -z "${requested_tools[$name]+selected}" ]]; then
    continue
  fi
  unset 'requested_tools[$name]'
  archive="${temporary_root}/${name}.artifact"
  curl --proto '=https' --tlsv1.2 -fsSL --connect-timeout 10 --max-time 300 \
    "$url" -o "$archive"
  actual="$("$uv_binary" run python - "$archive" <<'PY'
import hashlib
import sys

value = hashlib.sha256()
with open(sys.argv[1], "rb") as stream:
    for block in iter(lambda: stream.read(1024 * 1024), b""):
        value.update(block)
print(value.hexdigest())
PY
)"
  [[ "$actual" == "$expected" ]] || {
    printf 'checksum mismatch for %s\n' "$name" >&2
    exit 1
  }
  case "$kind" in
    file)
      install -m 0755 "$archive" "${destination}/bin/${binary}"
      ;;
    tar)
      extracted="${temporary_root}/${name}.extracted"
      _extract_safe "$archive" "$extracted"
      [[ -f "${extracted}/${binary}" && ! -L "${extracted}/${binary}" ]]
      install -m 0755 "${extracted}/${binary}" "${destination}/bin/${name}"
      ;;
    bats-source)
      extracted="${temporary_root}/${name}.extracted"
      _extract_safe "$archive" "$extracted"
      [[ -f "${extracted}/${binary}" && ! -L "${extracted}/${binary}" ]]
      bash "${extracted}/${binary}" "$destination"
      ;;
    go-source)
      extracted="${temporary_root}/${name}.extracted"
      _extract_safe "$archive" "$extracted"
      source_root="${extracted}/${binary%/cmd/govulncheck}"
      (
        cd "$source_root"
        GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
          go build -trimpath -buildvcs=false -o "${destination}/bin/govulncheck" \
          ./cmd/govulncheck
      )
      ;;
    python-source)
      UV_TOOL_DIR="${destination}/uv-tools" UV_TOOL_BIN_DIR="${destination}/bin" \
        "$uv_binary" tool install --from "$archive" reuse
      ;;
  esac
done <"${temporary_root}/artifacts.tsv"

if (( ${#requested_tools[@]} > 0 )); then
  printf '%s\n' 'one or more requested tools are unknown' >&2
  exit 2
fi
executables=(actionlint bats cosign gitleaks govulncheck lychee reuse shellcheck syft trivy)
if (( ${#selected_tools[@]} > 0 )); then
  executables=("${selected_tools[@]}")
fi
for executable in "${executables[@]}"; do
  [[ -x "${destination}/bin/${executable}" ]]
done

printf 'locked toolchain installed in %s\n' "$destination"
