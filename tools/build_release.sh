#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

usage() {
  printf '%s\n' \
    'usage: tools/build_release.sh --version vMAJOR.MINOR.PATCH --source-commit SHA' \
    '       --images-manifest FILE --output DIRECTORY' >&2
  exit 2
}

version=""
source_commit=""
images_manifest=""
output_directory=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      [[ $# -ge 2 ]] || usage
      version="$2"
      shift 2
      ;;
    --source-commit)
      [[ $# -ge 2 ]] || usage
      source_commit="$2"
      shift 2
      ;;
    --images-manifest)
      [[ $# -ge 2 ]] || usage
      images_manifest="$2"
      shift 2
      ;;
    --output)
      [[ $# -ge 2 ]] || usage
      output_directory="$2"
      shift 2
      ;;
    *)
      usage
      ;;
  esac
done

[[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || usage
[[ "$source_commit" =~ ^[0-9a-f]{40}$ ]] || usage
[[ -n "$images_manifest" && -f "$images_manifest" && ! -L "$images_manifest" ]] || usage
[[ -n "$output_directory" ]] || usage
[[ "${SOURCE_DATE_EPOCH:-}" =~ ^[0-9]{9,10}$ ]] || {
  printf '%s\n' 'SOURCE_DATE_EPOCH must be an explicit Unix timestamp' >&2
  exit 2
}

repository_root="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
images_manifest="$(python3 - "$images_manifest" <<'PY'
import sys
from pathlib import Path

print(Path(sys.argv[1]).resolve(strict=True))
PY
)"
output_directory="$(python3 - "$output_directory" <<'PY'
import sys
from pathlib import Path

print(Path(sys.argv[1]).resolve())
PY
)"
[[ "$output_directory" != / && "$output_directory" != "$repository_root" ]] || {
  printf '%s\n' 'release output path is too broad' >&2
  exit 2
}
[[ ! -e "$output_directory" && ! -L "$output_directory" ]] || {
  printf '%s\n' 'release output path must not already exist' >&2
  exit 2
}
output_parent="$(dirname -- "$output_directory")"
install -d -m 0755 "$output_parent"
temporary_root="$(mktemp -d "${output_parent}/.ezopenpn-release.XXXXXXXX")"
trap 'case "$temporary_root" in "$output_parent"/.ezopenpn-release.*) rm -rf -- "$temporary_root" ;; esac' EXIT

python3 - \
  "$repository_root" \
  "$images_manifest" \
  "$repository_root/deploy/images.lock" \
  "$version" \
  "$source_commit" \
  "$SOURCE_DATE_EPOCH" \
  "$temporary_root" <<'PY'
from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tomllib
from pathlib import Path, PurePosixPath

root = Path(sys.argv[1])
image_manifest_path = Path(sys.argv[2])
upstream_lock_path = Path(sys.argv[3])
version = sys.argv[4]
source_commit = sys.argv[5]
timestamp = int(sys.argv[6])
output = Path(sys.argv[7])


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def image_entry(reference: object, digest: object) -> dict[str, str]:
    if not isinstance(reference, str) or not re.fullmatch(r"[a-z0-9][a-z0-9./_-]*", reference):
        raise SystemExit("invalid image repository")
    if not isinstance(digest, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
        raise SystemExit("invalid image digest")
    return {"reference": reference, "digest": digest}


image_manifest_raw = image_manifest_path.read_bytes()
image_manifest = json.loads(image_manifest_raw)
source = image_manifest.get("source")
if not isinstance(source, dict) or source.get("commit") != source_commit:
    raise SystemExit("image manifest source does not match release source")
project_images = image_manifest.get("images")
if not isinstance(project_images, list):
    raise SystemExit("project image manifest is invalid")
project_by_name = {
    item.get("name"): item
    for item in project_images
    if isinstance(item, dict) and isinstance(item.get("name"), str)
}
if set(project_by_name) != {"control", "xray", "cert-sync"}:
    raise SystemExit("project image manifest is incomplete")

upstream = tomllib.loads(upstream_lock_path.read_text(encoding="utf-8"))["images"]
images = {
    name: image_entry(project_by_name[name].get("reference"), project_by_name[name].get("digest"))
    for name in ("control", "xray", "cert-sync")
}
images["hysteria"] = image_entry(
    upstream["hysteria"].get("repository"), upstream["hysteria"].get("digest")
)
images["gateway"] = image_entry(
    upstream["caddy"].get("repository"), upstream["caddy"].get("digest")
)

tracked = subprocess.run(
    [
        "git",
        "-C",
        str(root),
        "ls-files",
        "-z",
        "--",
        "deploy",
        "installer",
        "LICENSE",
        "THIRD_PARTY_NOTICES.md",
    ],
    check=True,
    stdout=subprocess.PIPE,
).stdout.split(b"\0")
relative_paths = sorted(item.decode("utf-8") for item in tracked if item)
if not relative_paths:
    raise SystemExit("release payload is empty")

payload: dict[str, bytes] = {}
file_modes: dict[str, int] = {}
for relative in relative_paths:
    path = PurePosixPath(relative)
    if path.is_absolute() or ".." in path.parts:
        raise SystemExit("unsafe tracked path")
    source_path = root / relative
    status = source_path.lstat()
    if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
        raise SystemExit("release payload contains a non-regular file")
    payload[relative] = source_path.read_bytes()
    file_modes[relative] = 0o755 if status.st_mode & 0o111 else 0o644

manifest = {
    "schema": 1,
    "version": version,
    "source_commit": source_commit,
    "source_date_epoch": timestamp,
    "database_schema": {"minimum": "0001_initial", "maximum": "0001_initial"},
    "image_manifest_sha256": sha256_bytes(image_manifest_raw),
    "images": dict(sorted(images.items())),
    "files": {name: sha256_bytes(payload[name]) for name in sorted(payload)},
}
payload["manifest.json"] = (
    json.dumps(manifest, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
).encode("ascii")
file_modes["manifest.json"] = 0o644

directories: set[str] = set()
for name in payload:
    parent = PurePosixPath(name).parent
    while str(parent) != ".":
        directories.add(parent.as_posix())
        parent = parent.parent

archive_path = output / "ezopenpn-bundle.tar.gz"
with archive_path.open("wb") as raw_output:
    with gzip.GzipFile(
        filename="", mode="wb", fileobj=raw_output, compresslevel=9, mtime=timestamp
    ) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.GNU_FORMAT) as archive:
            for name in sorted(directories):
                information = tarfile.TarInfo(name)
                information.type = tarfile.DIRTYPE
                information.mode = 0o755
                information.uid = 0
                information.gid = 0
                information.uname = ""
                information.gname = ""
                information.mtime = timestamp
                archive.addfile(information)
            for name in sorted(payload):
                value = payload[name]
                information = tarfile.TarInfo(name)
                information.size = len(value)
                information.mode = file_modes[name]
                information.uid = 0
                information.gid = 0
                information.uname = ""
                information.gname = ""
                information.mtime = timestamp
                archive.addfile(information, io.BytesIO(value))

bootstrap = root / "installer/install.sh"
(output / "install.sh").write_bytes(bootstrap.read_bytes())
os.chmod(output / "install.sh", 0o755)
os.utime(output / "install.sh", (timestamp, timestamp))
archive_digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
(output / "SHA256SUMS").write_text(
    f"{archive_digest}  ezopenpn-bundle.tar.gz\n", encoding="ascii"
)
os.chmod(archive_path, 0o644)
os.chmod(output / "SHA256SUMS", 0o644)
os.utime(archive_path, (timestamp, timestamp))
os.utime(output / "SHA256SUMS", (timestamp, timestamp))
PY

mv -- "$temporary_root" "$output_directory"
trap - EXIT
printf 'release bundle created at %s\n' "$output_directory"
