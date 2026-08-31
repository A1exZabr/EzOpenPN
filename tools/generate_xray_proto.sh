#!/usr/bin/env bash
set -euo pipefail

readonly mode="${1:---check}"
case "$mode" in
  --check | --write) ;;
  *)
    echo "usage: tools/generate_xray_proto.sh [--check|--write]" >&2
    exit 2
    ;;
esac

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly repository_root
readonly schema_root="$repository_root/proto/xray"
readonly target_root="$repository_root/control/src/ezopenpn/integrations/xray_proto"
temporary_root="$(mktemp -d "${TMPDIR:-/tmp}/ezopenpn-xray-proto.XXXXXX")"
readonly temporary_root
trap 'rm -rf "$temporary_root"' EXIT
readonly generated_root="$temporary_root/xray_proto"
mkdir -p "$generated_root"

cd "$repository_root"
uv run python -m grpc_tools.protoc \
  -I "$schema_root" \
  --python_out="$generated_root" \
  --grpc_python_out="$generated_root" \
  "$schema_root/common/serial/typed_message.proto" \
  "$schema_root/common/protocol/user.proto" \
  "$schema_root/proxy/vless/account.proto" \
  "$schema_root/app/proxyman/command/command.proto"

while IFS= read -r generated_file; do
  sed -i.bak \
    -e 's/^from common\./from ezopenpn.integrations.xray_proto.common./' \
    -e 's/^from proxy\./from ezopenpn.integrations.xray_proto.proxy./' \
    -e 's/^from app\./from ezopenpn.integrations.xray_proto.app./' \
    "$generated_file"
  rm -f "$generated_file.bak"
done < <(find "$generated_root" -type f -name '*.py' -print)

while IFS= read -r generated_directory; do
  touch "$generated_directory/__init__.py"
done < <(find "$generated_root" -type d -print)

uv run python - "$generated_root" <<'PY'
from __future__ import annotations

import sys
from pathlib import Path

root = Path(sys.argv[1])
header = (
    "# SPDX-" + "License-Identifier: MPL-2.0\n"
    "# Derived from XTLS/Xray-core v26.3.27.\n"
)
for path in sorted(root.rglob("*.py")):
    path.write_text(header + path.read_text(encoding="utf-8"), encoding="utf-8")
PY

if [ "$mode" = "--write" ]; then
  mkdir -p "$target_root"
  rsync --archive --delete "$generated_root/" "$target_root/"
  exit 0
fi

if [ ! -d "$target_root" ]; then
  echo "generated Xray modules are missing; run with --write" >&2
  exit 1
fi

diff -ruN --exclude='__pycache__' "$target_root" "$generated_root"
