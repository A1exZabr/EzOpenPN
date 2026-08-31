#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

if [[ $# -ne 1 || "$1" != --check ]]; then
  printf '%s\n' 'usage: tools/lock_vm_images.sh --check' >&2
  exit 2
fi

repository_root="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
matrix_path="${repository_root}/tests/vm/matrix.toml"
temporary_root="$(mktemp -d "${TMPDIR:-/tmp}/ezopenpn-vm-lock.XXXXXXXX")"
trap 'case "$temporary_root" in "${TMPDIR:-/tmp}"/ezopenpn-vm-lock.*) rm -rf -- "$temporary_root" ;; esac' EXIT
rows="${temporary_root}/rows.tsv"
python_command=(python3)
if ! "${python_command[@]}" -c 'import tomllib' >/dev/null 2>&1; then
  if command -v uv >/dev/null 2>&1; then
    python_command=(uv run python)
  else
    printf '%s\n' 'Python 3.11 or newer is required to check the VM image lock.' >&2
    exit 69
  fi
fi

"${python_command[@]}" - "$matrix_path" >"$rows" <<'PY'
from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

matrix = tomllib.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if matrix.get("schema") != 1 or not isinstance(matrix.get("images"), dict):
    raise SystemExit("invalid VM image matrix")
expected = {"ubuntu-22.04", "ubuntu-24.04", "debian-12", "debian-13"}
if set(matrix["images"]) != expected:
    raise SystemExit("incomplete VM image matrix")
for name in sorted(matrix["images"]):
    image = matrix["images"][name]
    algorithm = image.get("manifest_algorithm")
    length = 64 if algorithm == "sha256" else 128 if algorithm == "sha512" else 0
    values = (
        image.get("manifest_url"),
        image.get("filename"),
        algorithm,
        image.get("manifest_checksum"),
        image.get("sha256"),
    )
    if not all(isinstance(value, str) and value for value in values):
        raise SystemExit(f"invalid VM image entry: {name}")
    if not values[0].startswith("https://"):
        raise SystemExit(f"invalid VM manifest URL: {name}")
    if re.fullmatch(rf"[0-9a-f]{{{length}}}", values[3]) is None:
        raise SystemExit(f"invalid upstream checksum: {name}")
    if re.fullmatch(r"[0-9a-f]{64}", values[4]) is None:
        raise SystemExit(f"invalid image checksum: {name}")
    print(name, *values[:4], sep="\t")
PY

while IFS=$'\t' read -r name manifest_url filename algorithm expected; do
  manifest="${temporary_root}/${name}.sums"
  curl --proto '=https' --tlsv1.2 -fsSL \
    --connect-timeout 10 --max-time 60 "$manifest_url" -o "$manifest"
  "${python_command[@]}" - "$manifest" "$filename" "$algorithm" "$expected" <<'PY'
from __future__ import annotations

import hmac
import re
import sys
from pathlib import Path

path, filename, algorithm, expected = sys.argv[1:]
length = 64 if algorithm == "sha256" else 128
pattern = re.compile(rf"^([0-9a-f]{{{length}}}) [ *]([^/]+)$")
matches = []
for line in Path(path).read_text(encoding="ascii").splitlines():
    match = pattern.fullmatch(line)
    if match is not None and match.group(2) == filename:
        matches.append(match.group(1))
if len(matches) != 1 or not hmac.compare_digest(matches[0], expected):
    raise SystemExit(f"upstream checksum changed for {filename}")
PY
done <"$rows"

printf '%s\n' 'VM image manifests match the locked checksums.'
