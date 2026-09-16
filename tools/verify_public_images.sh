#!/usr/bin/env bash

set -Eeuo pipefail
umask 077
[[ $# -eq 1 && -f "$1" ]] || exit 2
subjects="$(python3 - "$1" <<'PY'
import json
import re
import sys

images = json.load(open(sys.argv[1], encoding="utf-8"))["images"]
names = {"control", "xray", "hysteria", "cert-sync", "gateway"}
if len(images) != 5 or {item["name"] for item in images} != names:
    raise SystemExit("public image manifest is incomplete")
for item in images:
    if (item["reference"] != "ghcr.io/a1exzabr/ezopenpn-" + item["name"]
            or re.fullmatch(r"sha256:[0-9a-f]{64}", item["digest"]) is None):
        raise SystemExit("public image reference is invalid")
for item in images:
    print(item["reference"] + "@" + item["digest"])
PY
)"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/ezopenpn-anonymous.XXXXXXXX")"
trap 'case "$scratch" in "${TMPDIR:-/tmp}"/ezopenpn-anonymous.*) rm -rf -- "$scratch" ;; esac' EXIT
while IFS= read -r subject; do
  docker --config "$scratch" pull --platform linux/amd64 "$subject"
done <<<"$subjects"
