#!/bin/sh
set -eu

if [ "${1:-}" = "uvicorn" ]; then
  python -m ezopenpn.cli --config "$EZOPENPN_CONFIG_PATH" migrate
fi

exec "$@"
