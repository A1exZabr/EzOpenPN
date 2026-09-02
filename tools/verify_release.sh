#!/usr/bin/env bash

set -Eeuo pipefail

usage() {
  printf '%s\n' 'usage: tools/verify_release.sh [--signed] RELEASE_DIRECTORY' >&2
  exit 2
}

signed=0
if [[ "${1:-}" == --signed ]]; then
  signed=1
  shift
fi
[[ $# -eq 1 ]] || usage
release_directory="$1"
[[ -d "$release_directory" && ! -L "$release_directory" ]] || usage
release_directory="$(cd -P -- "$release_directory" && pwd)"

python3 - "$release_directory" <<'PY'
from __future__ import annotations

import hashlib
import json
import re
import stat
import sys
import tarfile
from pathlib import Path, PurePosixPath

root = Path(sys.argv[1])
archive_path = root / "ezopenpn-bundle.tar.gz"
checksum_path = root / "SHA256SUMS"
bootstrap_path = root / "install.sh"
for path in (archive_path, checksum_path, bootstrap_path):
    status = path.lstat()
    if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
        raise SystemExit("release asset is not a regular file")
if archive_path.stat().st_size > 64 * 1024 * 1024:
    raise SystemExit("release archive is unexpectedly large")
checksum = checksum_path.read_text(encoding="ascii")
match = re.fullmatch(r"([0-9a-f]{64})  ezopenpn-bundle\.tar\.gz\n", checksum)
if match is None:
    raise SystemExit("checksum file is invalid")
if hashlib.sha256(archive_path.read_bytes()).hexdigest() != match.group(1):
    raise SystemExit("release archive checksum mismatch")

allowed_roots = {
    "deploy",
    "installer",
    "manifest.json",
    "LICENSE",
    "THIRD_PARTY_NOTICES.md",
}
with tarfile.open(archive_path, "r:gz") as archive:
    members = archive.getmembers()
    names: set[str] = set()
    files: dict[str, bytes] = {}
    timestamps: set[int] = set()
    for member in members:
        path = PurePosixPath(member.name)
        if (
            path.is_absolute()
            or ".." in path.parts
            or not path.parts
            or path.parts[0] not in allowed_roots
            or member.name in names
            or member.issym()
            or member.islnk()
            or not (member.isdir() or member.isfile())
            or member.uid != 0
            or member.gid != 0
        ):
            raise SystemExit("release archive member is unsafe")
        names.add(member.name)
        timestamps.add(int(member.mtime))
        if member.isfile():
            stream = archive.extractfile(member)
            if stream is None:
                raise SystemExit("release file cannot be read")
            files[member.name] = stream.read()
if len(timestamps) != 1 or "manifest.json" not in files:
    raise SystemExit("release timestamps or manifest are invalid")
manifest = json.loads(files["manifest.json"])
if manifest.get("schema") != 1:
    raise SystemExit("release manifest schema is invalid")
if re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", str(manifest.get("version"))) is None:
    raise SystemExit("release version is invalid")
if re.fullmatch(r"[0-9a-f]{40}", str(manifest.get("source_commit"))) is None:
    raise SystemExit("release source commit is invalid")
if manifest.get("source_date_epoch") != next(iter(timestamps)):
    raise SystemExit("release timestamp does not match manifest")
if manifest.get("database_schema") != {
    "minimum": "0001_initial",
    "maximum": "0001_initial",
}:
    raise SystemExit("release database schema range is invalid")
images = manifest.get("images")
if not isinstance(images, dict) or set(images) != {
    "control",
    "xray",
    "hysteria",
    "gateway",
    "cert-sync",
}:
    raise SystemExit("release image set is invalid")
for image in images.values():
    if not isinstance(image, dict):
        raise SystemExit("release image entry is invalid")
    reference = image.get("reference")
    digest = image.get("digest")
    if not isinstance(reference, str) or re.fullmatch(r"[a-z0-9][a-z0-9./_-]*", reference) is None:
        raise SystemExit("release image repository is invalid")
    if not isinstance(digest, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
        raise SystemExit("release image digest is invalid")
expected_files = manifest.get("files")
actual_names = set(files) - {"manifest.json"}
if not isinstance(expected_files, dict) or set(expected_files) != actual_names:
    raise SystemExit("release file manifest is incomplete")
for name, expected in expected_files.items():
    if not isinstance(expected, str) or re.fullmatch(r"[0-9a-f]{64}", expected) is None:
        raise SystemExit("release file checksum is invalid")
    if hashlib.sha256(files[name]).hexdigest() != expected:
        raise SystemExit("release payload checksum mismatch")
if files.get("installer/install.sh") != bootstrap_path.read_bytes():
    raise SystemExit("bootstrap asset does not match bundled source")
print(manifest["version"])
print(manifest["source_commit"])
PY

if (( signed == 1 )); then
  for command_name in cosign; do
    command -v "$command_name" >/dev/null 2>&1 || {
      printf 'required signed-release tool is unavailable: %s\n' "$command_name" >&2
      exit 127
    }
  done
  required=(
    ezopenpn-bundle.sigstore.json
    ezopenpn-bundle.sig
    ezopenpn-bundle.pem
    SHA256SUMS.sigstore.json
    SHA256SUMS.sig
    SHA256SUMS.pem
    ezopenpn-bundle.spdx.json
  )
  for asset in "${required[@]}"; do
    [[ -f "${release_directory}/${asset}" && ! -L "${release_directory}/${asset}" ]] || {
      printf 'signed release asset is missing: %s\n' "$asset" >&2
      exit 1
    }
  done
  readarray -t release_metadata < <(python3 - "$release_directory/ezopenpn-bundle.tar.gz" <<'PY'
import json
import sys
import tarfile

with tarfile.open(sys.argv[1], "r:gz") as archive:
    stream = archive.extractfile("manifest.json")
    if stream is None:
        raise SystemExit(1)
    manifest = json.load(stream)
print(manifest["version"])
print(manifest["source_commit"])
PY
)
  version="${release_metadata[0]}"
  identity=""
  for workflow in release.yml candidate-release.yml; do
    candidate_identity="https://github.com/A1exZabr/EzOpenPN/.github/workflows/${workflow}@refs/tags/${version}"
    if cosign verify-blob "${release_directory}/ezopenpn-bundle.tar.gz" \
      --bundle "${release_directory}/ezopenpn-bundle.sigstore.json" \
      --certificate-identity "$candidate_identity" \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com >/dev/null 2>&1 \
      && cosign verify-blob "${release_directory}/SHA256SUMS" \
        --bundle "${release_directory}/SHA256SUMS.sigstore.json" \
        --certificate-identity "$candidate_identity" \
        --certificate-oidc-issuer https://token.actions.githubusercontent.com >/dev/null 2>&1; then
      identity="$candidate_identity"
      break
    fi
  done
  [[ -n "$identity" ]] || {
    printf '%s\n' 'release signature identity is invalid' >&2
    exit 1
  }
  python3 - "${release_directory}/ezopenpn-bundle.spdx.json" <<'PY'
import json
import sys
from pathlib import Path

document = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if not str(document.get("spdxVersion", "")).startswith("SPDX-"):
    raise SystemExit("release SBOM is invalid")
PY
fi

printf 'release assets verified in %s\n' "$release_directory"
