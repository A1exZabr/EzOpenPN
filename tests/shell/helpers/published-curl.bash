#!/usr/bin/env bash
set -euo pipefail
url="" destination=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    https://*) url="$1"; shift ;;
    -o) destination="$2"; shift 2 ;;
    *) shift ;;
  esac
done
[[ "$url" == https://git.alexzabrodin.pro/ezopenpn/releases/download/v0.1.0/* ]]
[[ -n "$destination" ]]
printf '%s\n' "$url" >>"$TEST_PUBLISHED_REQUESTS"
cp "$TEST_PUBLISHED_ROOT/${url##*/}" "$destination"
