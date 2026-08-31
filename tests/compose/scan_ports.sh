#!/usr/bin/env bash
set -euo pipefail

if [[ ${1:-} == "--help" ]]; then
  echo "usage: scan_ports.sh HOST [SSH_PORT]"
  exit 0
fi
if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: scan_ports.sh HOST [SSH_PORT]" >&2
  exit 64
fi

host="$1"
ssh_port="${2:-}"
host="$(python3 - "$host" <<'PY'
from __future__ import annotations

import ipaddress
import sys

address = ipaddress.ip_address(sys.argv[1])
if address.version != 4:
    raise SystemExit("HOST must be an IPv4 address")
print(address)
PY
)"
if [[ -n "$ssh_port" ]]; then
  if [[ ! "$ssh_port" =~ ^[0-9]+$ ]] || (( ssh_port < 1 || ssh_port > 65535 )); then
    echo "SSH_PORT must be between 1 and 65535" >&2
    exit 64
  fi
fi

nmap_bin="${NMAP_BIN:-nmap}"
if [[ "$nmap_bin" == */* ]]; then
  if [[ ! -x "$nmap_bin" ]]; then
    echo "NMAP_BIN is not executable" >&2
    exit 69
  fi
elif ! command -v "$nmap_bin" >/dev/null 2>&1; then
  echo "nmap is required" >&2
  exit 69
fi
if [[ -z "${NMAP_BIN:-}" && ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "run this scan as root so UDP state can be checked" >&2
  exit 77
fi

scan_root="$(mktemp -d "${TMPDIR:-/tmp}/ezopenpn-port-scan.XXXXXX")"
cleanup() {
  case "$scan_root" in
    "${TMPDIR:-/tmp}"/ezopenpn-port-scan.*) rm -rf -- "$scan_root" ;;
    *) echo "refusing to remove an unexpected scan directory" >&2 ;;
  esac
}
trap cleanup EXIT

"$nmap_bin" -Pn -n -sT -T4 --max-retries 1 --host-timeout 90s \
  -p- -oX - "$host" >"${scan_root}/tcp.xml"
"$nmap_bin" -Pn -n -sU -T4 --max-retries 1 --host-timeout 45s \
  -p 443 -oX - "$host" >"${scan_root}/udp.xml"

python3 - \
  "$host" \
  "$ssh_port" \
  "${scan_root}/tcp.xml" \
  "${scan_root}/udp.xml" <<'PY'
from __future__ import annotations

import ipaddress
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

host = ipaddress.ip_address(sys.argv[1])
ssh_port = int(sys.argv[2]) if sys.argv[2] else None
tcp_path = Path(sys.argv[3])
udp_path = Path(sys.argv[4])


def states(path: Path, protocol: str) -> dict[int, str]:
    root = ET.parse(path).getroot()
    result: dict[int, str] = {}
    for port in root.findall(f".//port[@protocol='{protocol}']"):
        state = port.find("state")
        if state is not None:
            result[int(port.attrib["portid"])] = state.attrib["state"]
    return result


tcp_states = states(tcp_path, "tcp")
udp_states = states(udp_path, "udp")
observed_tcp = {port for port, state in tcp_states.items() if state == "open"}
observed_udp = {
    port
    for port, state in udp_states.items()
    if state == "open" or (host.is_loopback and state == "open|filtered")
}
uncertain_udp = {
    port
    for port, state in udp_states.items()
    if not host.is_loopback and state == "open|filtered"
}

expected_tcp = {80, 443, 9443}
if ssh_port is not None:
    expected_tcp.add(ssh_port)
expected_udp = {443}
unexpected_tcp = observed_tcp - expected_tcp
unexpected_udp = observed_udp - expected_udp
missing_tcp = expected_tcp - observed_tcp
missing_udp = expected_udp - observed_udp
ok = not (unexpected_tcp or unexpected_udp or missing_tcp or missing_udp)

report = {
    "expected": {
        "tcp": sorted(expected_tcp),
        "udp": sorted(expected_udp),
    },
    "missing": {
        "tcp": sorted(missing_tcp),
        "udp": sorted(missing_udp),
    },
    "observed": {
        "tcp": sorted(observed_tcp),
        "udp": sorted(observed_udp),
    },
    "ok": ok,
    "target": str(host),
    "uncertain": {"udp": sorted(uncertain_udp)},
    "unexpected": {
        "tcp": sorted(unexpected_tcp),
        "udp": sorted(unexpected_udp),
    },
}
print(json.dumps(report, separators=(",", ":"), sort_keys=True))
raise SystemExit(0 if ok else 1)
PY
