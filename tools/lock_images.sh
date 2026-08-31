#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: tools/lock_images.sh --check|--write" >&2
  exit 64
}

if [[ $# -ne 1 ]]; then
  usage
fi

mode="$1"
if [[ "$mode" != "--check" && "$mode" != "--write" ]]; then
  usage
fi

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
sources_path="${repository_root}/deploy/images.toml"
lock_path="${repository_root}/deploy/images.lock"
temporary_root="$(mktemp -d "${TMPDIR:-/tmp}/ezopenpn-images.XXXXXX")"
trap 'rm -rf -- "$temporary_root"' EXIT
source_rows="${temporary_root}/sources.tsv"
candidate_lock="${temporary_root}/images.lock"

command -v docker >/dev/null 2>&1 || {
  echo "docker is required to resolve image locks" >&2
  exit 69
}
docker buildx version >/dev/null

python3 - "$sources_path" >"$source_rows" <<'PY'
from __future__ import annotations

import sys
import tomllib
from pathlib import Path

source = tomllib.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))["images"]
for name in sorted(source):
    image = source[name]
    print(name, image["repository"], image["version"], sep="\t")
PY

: >"$candidate_lock"
while IFS=$'\t' read -r name repository version; do
  if [[ ! "$name" =~ ^[a-z0-9-]+$ || ! "$repository" =~ ^[a-z0-9./_-]+$ ]]; then
    echo "invalid image declaration: ${name}" >&2
    exit 65
  fi
  reference="${repository}:${version}"
  raw_manifest="$(docker buildx imagetools inspect --raw "$reference")"
  digest="$(RAW_MANIFEST="$raw_manifest" python3 - <<'PY'
from __future__ import annotations

import json
import os

manifest = json.loads(os.environ["RAW_MANIFEST"])
matches = [
    item["digest"]
    for item in manifest.get("manifests", [])
    if item.get("platform", {}).get("os") == "linux"
    and item.get("platform", {}).get("architecture") == "amd64"
    and not item.get("platform", {}).get("variant")
]
if len(matches) != 1:
    raise SystemExit("image does not contain exactly one linux/amd64 manifest")
print(matches[0])
PY
)"
  if [[ ! "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    echo "invalid resolved digest for ${name}" >&2
    exit 65
  fi
  {
    printf '[images.%s]\n' "$name"
    printf 'repository = "%s"\n' "$repository"
    printf 'version = "%s"\n' "$version"
    printf 'platform = "linux/amd64"\n'
    printf 'digest = "%s"\n\n' "$digest"
  } >>"$candidate_lock"
done <"$source_rows"

if [[ "$mode" == "--check" ]]; then
  if ! cmp -s "$candidate_lock" "$lock_path"; then
    echo "deploy/images.lock does not match current linux/amd64 manifests" >&2
    exit 1
  fi
  echo "image lock is current"
  exit 0
fi

chmod 0644 "$candidate_lock"
mv -f -- "$candidate_lock" "$lock_path"
echo "updated deploy/images.lock"
