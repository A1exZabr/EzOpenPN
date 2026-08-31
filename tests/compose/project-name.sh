#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: project-name.sh STACK_ROOT" >&2
  exit 64
fi

root_name="$(basename -- "$1")"
if [[ "$root_name" != ezopenpn-stack.* ]]; then
  echo "stack root name is invalid" >&2
  exit 65
fi
suffix="${root_name#ezopenpn-stack.}"
normalized="$(printf '%s' "$suffix" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9')"
if [[ -z "$normalized" ]]; then
  echo "stack root suffix is invalid" >&2
  exit 65
fi
normalized="$(printf '%s' "$normalized" | tail -c 12)"
printf 'ezop-stack-%s\n' "$normalized"
