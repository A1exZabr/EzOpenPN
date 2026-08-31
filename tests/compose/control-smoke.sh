#!/usr/bin/env bash
set -euo pipefail

readonly image_name="ezopenpn-control:test"

test -f control/Dockerfile
command -v docker >/dev/null 2>&1 || {
  echo "docker is required for the control image smoke test" >&2
  exit 127
}

docker build -f control/Dockerfile -t "$image_name" .
test "$(docker image inspect "$image_name" --format '{{.Config.User}}')" = "10001:10001"
docker run --rm "$image_name" python -m ezopenpn.cli --help >/dev/null
