#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
lock_path="${repository_root}/deploy/images.lock"
caddyfile_path="${repository_root}/deploy/caddy/Caddyfile"

if [[ -z "${PUBLIC_IP:-}" ]]; then
  echo "PUBLIC_IP is required" >&2
  exit 64
fi

python3 - "$PUBLIC_IP" <<'PY'
from __future__ import annotations

import ipaddress
import sys

value = ipaddress.ip_address(sys.argv[1])
if value.version != 4:
    raise SystemExit("PUBLIC_IP must be IPv4")
PY

image_reference="$(python3 - "$lock_path" <<'PY'
from __future__ import annotations

import sys
import tomllib
from pathlib import Path

image = tomllib.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))["images"]["caddy"]
print(f'{image["repository"]}@{image["digest"]}')
PY
)"

docker run --rm \
  --network none \
  --env PUBLIC_IP="$PUBLIC_IP" \
  --mount "type=bind,src=${caddyfile_path},dst=/etc/caddy/Caddyfile,readonly" \
  --entrypoint caddy \
  "$image_reference" \
  adapt --config /etc/caddy/Caddyfile --adapter caddyfile --validate --pretty
