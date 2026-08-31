#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: test-ip-cert.sh OUTPUT_DIRECTORY IPV4" >&2
  exit 64
fi

output_directory="$1"
ip_value="$2"
python3 - "$ip_value" <<'PY'
from __future__ import annotations

import ipaddress
import sys

value = ipaddress.ip_address(sys.argv[1])
if value.version != 4:
    raise SystemExit("test certificate address must be IPv4")
PY

umask 077
mkdir -p "$output_directory"
extensions_path="${output_directory}/extensions.cnf"
{
  printf '%s\n' '[req]'
  printf '%s\n' 'distinguished_name = subject'
  printf '%s\n' 'req_extensions = v3_req'
  printf '%s\n' '[subject]'
  printf '%s\n' '[v3_req]'
  printf '%s\n' 'subjectAltName = @alternative_names'
  printf '%s\n' '[alternative_names]'
  printf 'IP.1 = %s\n' "$ip_value"
} >"$extensions_path"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -subj "/CN=EzOpenPN local test root" \
  -keyout "${output_directory}/ca.key" \
  -out "${output_directory}/ca.crt" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
  -subj "/CN=${ip_value}" \
  -config "$extensions_path" \
  -reqexts v3_req \
  -keyout "${output_directory}/server.key" \
  -out "${output_directory}/server.csr" >/dev/null 2>&1
openssl x509 -req -days 1 \
  -in "${output_directory}/server.csr" \
  -CA "${output_directory}/ca.crt" \
  -CAkey "${output_directory}/ca.key" \
  -CAcreateserial \
  -extfile "$extensions_path" \
  -extensions v3_req \
  -out "${output_directory}/server.crt" >/dev/null 2>&1
chmod 0644 "${output_directory}/ca.crt" "${output_directory}/server.crt"
chmod 0600 "${output_directory}/ca.key" "${output_directory}/server.key"
