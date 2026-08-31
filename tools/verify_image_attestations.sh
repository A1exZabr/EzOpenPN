#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

usage() {
  printf '%s\n' \
    'usage: tools/verify_image_attestations.sh --fixture MANIFEST' \
    '       tools/verify_image_attestations.sh --manifest MANIFEST --sbom-dir DIRECTORY' >&2
  exit 2
}

mode="${1:-}"
manifest="${2:-}"
sbom_directory=""
case "$mode" in
  --fixture)
    [[ $# -eq 2 ]] || usage
    ;;
  --manifest)
    [[ $# -eq 4 && "${3:-}" == --sbom-dir ]] || usage
    sbom_directory="${4:-}"
    [[ "$sbom_directory" == /* && -d "$sbom_directory" ]] || {
      printf '%s\n' 'SBOM directory must be an existing absolute directory' >&2
      exit 2
    }
    ;;
  *)
    usage
    ;;
esac
[[ -f "$manifest" && ! -L "$manifest" ]] || {
  printf '%s\n' 'image manifest must be a regular file' >&2
  exit 2
}

temporary_root="$(mktemp -d "${TMPDIR:-/tmp}/ezopenpn-image-verify.XXXXXXXX")"
trap 'case "$temporary_root" in /tmp/ezopenpn-image-verify.* | "${TMPDIR:-/tmp}"/ezopenpn-image-verify.*) rm -rf -- "$temporary_root" ;; esac' EXIT
rows="${temporary_root}/images.tsv"

python3 - "$manifest" >"$rows" <<'PY'
from __future__ import annotations

import json
import re
import sys
from pathlib import Path, PurePosixPath

path = Path(sys.argv[1])
payload = json.loads(path.read_text(encoding="utf-8"))
if payload.get("schema") != 1:
    raise SystemExit("unsupported image manifest schema")
source = payload.get("source")
if not isinstance(source, dict):
    raise SystemExit("image manifest source is missing")
repository = source.get("repository")
commit = source.get("commit")
if repository != "A1exZabr/EzOpenPN":
    raise SystemExit("unexpected source repository")
if not isinstance(commit, str) or re.fullmatch(r"[0-9a-f]{40}", commit) is None:
    raise SystemExit("invalid source commit")
images = payload.get("images")
if not isinstance(images, list) or len(images) != 3:
    raise SystemExit("image manifest must contain three images")
expected = {"control", "xray", "cert-sync"}
seen: set[str] = set()
for image in images:
    if not isinstance(image, dict):
        raise SystemExit("invalid image entry")
    name = image.get("name")
    if name not in expected or name in seen:
        raise SystemExit("invalid or duplicate image name")
    seen.add(name)
    reference = image.get("reference")
    expected_reference = f"ghcr.io/a1exzabr/ezopenpn-{name}"
    if reference != expected_reference or ":latest" in reference:
        raise SystemExit("invalid image reference")
    digest = image.get("digest")
    if not isinstance(digest, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
        raise SystemExit("invalid image digest")
    sbom_path = image.get("sbom_path")
    if sbom_path != f"{name}.spdx.json":
        raise SystemExit("invalid SBOM path")
    parsed_sbom_path = PurePosixPath(sbom_path)
    if parsed_sbom_path.is_absolute() or ".." in parsed_sbom_path.parts:
        raise SystemExit("unsafe SBOM path")
    sbom_sha256 = image.get("sbom_sha256")
    if not isinstance(sbom_sha256, str) or re.fullmatch(r"[0-9a-f]{64}", sbom_sha256) is None:
        raise SystemExit("invalid SBOM checksum")
    subject = image.get("provenance_subject")
    if subject != f"{reference}@{digest}":
        raise SystemExit("provenance subject does not match image")
    identity = image.get("workflow_identity")
    prefix = "https://github.com/A1exZabr/EzOpenPN/.github/workflows/images.yml@refs/"
    if not isinstance(identity, str) or not identity.startswith(prefix):
        raise SystemExit("invalid workflow identity")
    if any(character in identity for character in "\t\r\n"):
        raise SystemExit("invalid workflow identity")
    print(
        "\t".join(
            (name, reference, digest, sbom_path, sbom_sha256, subject, identity, commit)
        )
    )
if seen != expected:
    raise SystemExit("image manifest is incomplete")
PY

if [[ "$mode" == --fixture ]]; then
  printf '%s\n' 'image manifest fixture is valid'
  exit 0
fi

for command_name in cosign gh; do
  command -v "$command_name" >/dev/null 2>&1 || {
    printf 'required verification tool is unavailable: %s\n' "$command_name" >&2
    exit 127
  }
done

verified=0
while IFS=$'\t' read -r name reference digest sbom_path expected_sbom subject identity commit; do
  candidate="${sbom_directory}/${sbom_path}"
  [[ -f "$candidate" && ! -L "$candidate" ]] || {
    printf 'SBOM is missing for %s\n' "$name" >&2
    exit 1
  }
  actual_sbom="$(python3 - "$candidate" <<'PY'
import hashlib
import json
import sys

value = hashlib.sha256()
with open(sys.argv[1], "rb") as stream:
    for block in iter(lambda: stream.read(1024 * 1024), b""):
        value.update(block)
with open(sys.argv[1], encoding="utf-8") as stream:
    payload = json.load(stream)
if not str(payload.get("spdxVersion", "")).startswith("SPDX-"):
    raise SystemExit("invalid SPDX document")
print(value.hexdigest())
PY
)"
  [[ "$actual_sbom" == "$expected_sbom" ]] || {
    printf 'SBOM checksum mismatch for %s\n' "$name" >&2
    exit 1
  }
  cosign verify \
    --certificate-identity "$identity" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    "${reference}@${digest}" >/dev/null
  gh attestation verify "oci://${subject}" \
    --repo A1exZabr/EzOpenPN \
    --cert-identity "$identity" \
    --source-digest "$commit" \
    --deny-self-hosted-runners >/dev/null
  verified=$((verified + 1))
done <"$rows"

printf 'verified %d signed image(s) with provenance and SBOM checksums\n' "$verified"
