from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Any

_MAX_INPUT_BYTES = 64 * 1024
_BIND_ALL_IPV4 = "0.0.0.0"  # nosec B104
_HOST_PATTERN = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
)
_KEY_PATTERN = re.compile(r"[A-Za-z0-9_-]{42,44}")
_SHORT_ID_PATTERN = re.compile(r"[0-9a-f]{16}")
_PATH_PATTERN = re.compile(r"/[A-Za-z0-9_-]{24}")


class RenderError(RuntimeError):
    pass


def _read_regular(path: Path, *, maximum: int = _MAX_INPUT_BYTES) -> bytes:
    try:
        status = path.lstat()
        if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
            raise RenderError("input must be a regular file")
        if status.st_size > maximum:
            raise RenderError("input file is too large")
        return path.read_bytes()
    except OSError:
        raise RenderError("input file is unavailable") from None


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(_read_regular(path))
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise RenderError("configuration material is invalid") from None
    if not isinstance(value, dict):
        raise RenderError("configuration material is invalid")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise RenderError(f"{label} is invalid")
    return value


def _key(value: object, label: str) -> str:
    text = _string(value, label)
    if _KEY_PATTERN.fullmatch(text) is None:
        raise RenderError(f"{label} is invalid")
    try:
        decoded = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except ValueError:
        raise RenderError(f"{label} is invalid") from None
    if len(decoded) != 32:
        raise RenderError(f"{label} is invalid")
    return text


def _encoded_secret(value: object, label: str) -> str:
    text = _string(value, label)
    try:
        decoded = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except ValueError:
        raise RenderError(f"{label} is invalid") from None
    if len(decoded) != 32:
        raise RenderError(f"{label} is invalid")
    return text


def _limits(value: object, label: str) -> dict[str, int]:
    if not isinstance(value, dict) or set(value) != {
        "after_bytes",
        "bytes_per_second",
        "burst_bytes_per_second",
    }:
        raise RenderError(f"{label} is invalid")
    if not all(isinstance(item, int) and not isinstance(item, bool) for item in value.values()):
        raise RenderError(f"{label} is invalid")
    normalized = {name: int(item) for name, item in value.items()}
    if not 1_048_576 <= normalized["after_bytes"] <= 67_108_864:
        raise RenderError(f"{label} is invalid")
    if not 131_072 <= normalized["bytes_per_second"] <= 8_388_608:
        raise RenderError(f"{label} is invalid")
    if not (normalized["bytes_per_second"] <= normalized["burst_bytes_per_second"] <= 33_554_432):
        raise RenderError(f"{label} is invalid")
    return normalized


def _validated_values(
    runtime: dict[str, Any], node: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    if set(runtime) != {"xray", "hysteria"}:
        raise RenderError("runtime material has unexpected fields")
    xray_value = runtime["xray"]
    hysteria_value = runtime["hysteria"]
    if not isinstance(xray_value, dict) or not isinstance(hysteria_value, dict):
        raise RenderError("runtime material is invalid")
    if set(xray_value) != {
        "target",
        "server_name",
        "private_key",
        "short_id",
        "xhttp_path",
        "fallback_upload",
        "fallback_download",
    }:
        raise RenderError("Xray material has unexpected fields")
    if set(hysteria_value) != {
        "certificate_path",
        "private_key_path",
        "obfs_password",
        "stats_secret",
    }:
        raise RenderError("Hysteria2 material has unexpected fields")
    if set(node) != {
        "server_name",
        "target",
        "xhttp_path",
        "xray_public_key",
        "xray_short_id",
    }:
        raise RenderError("node material has unexpected fields")

    server_name = _string(xray_value["server_name"], "server name")
    target = _string(xray_value["target"], "target")
    short_id = _string(xray_value["short_id"], "short ID")
    xhttp_path = _string(xray_value["xhttp_path"], "XHTTP path")
    if _HOST_PATTERN.fullmatch(server_name) is None or target != f"{server_name}:443":
        raise RenderError("target is invalid")
    if _SHORT_ID_PATTERN.fullmatch(short_id) is None:
        raise RenderError("short ID is invalid")
    if _PATH_PATTERN.fullmatch(xhttp_path) is None:
        raise RenderError("XHTTP path is invalid")
    if (
        node["server_name"] != server_name
        or node["target"] != target
        or node["xray_short_id"] != short_id
        or node["xhttp_path"] != xhttp_path
    ):
        raise RenderError("node and runtime material do not match")
    upload = _limits(xray_value["fallback_upload"], "upload fallback")
    download = _limits(xray_value["fallback_download"], "download fallback")
    if upload == download:
        raise RenderError("fallback limits must differ")

    xray = {
        "target": target,
        "server_name": server_name,
        "private_key": _key(xray_value["private_key"], "private key"),
        "public_key": _key(node["xray_public_key"], "public key"),
        "short_id": short_id,
        "xhttp_path": xhttp_path,
        "fallback_upload": upload,
        "fallback_download": download,
    }
    hysteria = {
        "certificate_path": _string(hysteria_value["certificate_path"], "certificate path"),
        "private_key_path": _string(hysteria_value["private_key_path"], "private key path"),
        "obfs_password": _encoded_secret(hysteria_value["obfs_password"], "obfuscation value"),
        "stats_secret": _encoded_secret(hysteria_value["stats_secret"], "statistics value"),
    }
    if hysteria["certificate_path"] != "/certs/fullchain.pem":
        raise RenderError("certificate path is invalid")
    if hysteria["private_key_path"] != "/certs/privkey.pem":
        raise RenderError("private key path is invalid")
    return xray, hysteria


def _xray_config(values: dict[str, Any]) -> str:
    config = {
        "log": {"access": "none", "dnsLog": False, "loglevel": "warning"},
        "api": {"tag": "api", "services": ["HandlerService"]},
        "inbounds": [
            {
                "listen": _BIND_ALL_IPV4,
                "port": 8443,
                "protocol": "vless",
                "tag": "protected-entry",
                "settings": {"clients": [], "decryption": "none"},
                "streamSettings": {
                    "network": "xhttp",
                    "security": "reality",
                    "xhttpSettings": {"mode": "auto", "path": values["xhttp_path"]},
                    "realitySettings": {
                        "show": False,
                        "target": values["target"],
                        "xver": 0,
                        "serverNames": [values["server_name"]],
                        "privateKey": values["private_key"],
                        "shortIds": [values["short_id"]],
                        "limitFallbackUpload": {
                            "afterBytes": values["fallback_upload"]["after_bytes"],
                            "bytesPerSec": values["fallback_upload"]["bytes_per_second"],
                            "burstBytesPerSec": values["fallback_upload"]["burst_bytes_per_second"],
                        },
                        "limitFallbackDownload": {
                            "afterBytes": values["fallback_download"]["after_bytes"],
                            "bytesPerSec": values["fallback_download"]["bytes_per_second"],
                            "burstBytesPerSec": values["fallback_download"][
                                "burst_bytes_per_second"
                            ],
                        },
                    },
                },
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls", "quic"],
                    "routeOnly": True,
                },
            },
            {
                "listen": _BIND_ALL_IPV4,
                "port": 10085,
                "protocol": "dokodemo-door",
                "tag": "api-in",
                "settings": {"address": "127.0.0.1"},
            },
        ],
        "outbounds": [
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "block"},
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {
                    "type": "field",
                    "inboundTag": ["api-in"],
                    "outboundTag": "api",
                }
            ],
        },
    }
    return json.dumps(config, ensure_ascii=True, indent=2, sort_keys=False) + "\n"


def _quote(value: object) -> str:
    return json.dumps(value, ensure_ascii=True)


def _hysteria_config(values: dict[str, Any], masquerade: str) -> str:
    return "\n".join(
        (
            'listen: "0.0.0.0:8443"',
            "",
            "tls:",
            f"  cert: {_quote(values['certificate_path'])}",
            f"  key: {_quote(values['private_key_path'])}",
            "  sniGuard: dns-san",
            "",
            "obfs:",
            "  type: salamander",
            "  salamander:",
            f"    password: {_quote(values['obfs_password'])}",
            "",
            "auth:",
            "  type: http",
            "  http:",
            '    url: "http://control:8000/internal/hysteria/auth"',
            "    insecure: false",
            "",
            "trafficStats:",
            '  listen: "0.0.0.0:9999"',
            f"  secret: {_quote(values['stats_secret'])}",
            "",
            "speedTest: false",
            "disableUDP: false",
            "udpIdleTimeout: 60s",
            "",
            "masquerade:",
            "  type: string",
            "  string:",
            f"    content: {_quote(masquerade)}",
            "    headers:",
            '      content-type: "text/html; charset=utf-8"',
            '      cache-control: "no-store"',
            "    statusCode: 200",
            "",
        )
    )


def _control_config(public_ip: str, values: dict[str, Any]) -> str:
    return "\n".join(
        (
            "[app]",
            f"public_ip = {_quote(public_ip)}",
            "",
            "[database]",
            'path = "/var/lib/ezopenpn/ezopenpn.sqlite3"',
            "",
            "[paths]",
            'master_key_path = "/run/secrets/ezopenpn_master_key"',
            'hysteria_api_path = "/run/secrets/ezopenpn_hysteria_api"',
            'hysteria_obfs_path = "/run/secrets/ezopenpn_hysteria_obfs"',
            'supervisor_socket = "/run/ezopenpn-xray/control.sock"',
            "",
            "[proxy]",
            'trusted_hosts = ["gateway"]',
            "",
            "[xray]",
            'grpc_target = "xray:10085"',
            'inbound_tag = "protected-entry"',
            f"reality_public_key = {_quote(values['public_key'])}",
            f"reality_server_name = {_quote(values['server_name'])}",
            f"reality_short_id = {_quote(values['short_id'])}",
            f"xhttp_path = {_quote(values['xhttp_path'])}",
            "",
            "[hysteria]",
            'stats_url = "http://hysteria:9999"',
            "",
            "[session]",
            "idle_seconds = 43200",
            "absolute_seconds = 604800",
            "",
        )
    )


def _atomic_write(path: Path, content: bytes, mode: int) -> None:
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise RenderError("output path is unsafe")
    if not path.parent.is_dir() or path.parent.is_symlink():
        raise RenderError("output directory is unsafe")
    descriptor, raw_temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(raw_temporary)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def render(
    *,
    values_path: Path,
    node_path: Path,
    public_ip: str,
    deploy_root: Path,
    etc_root: Path,
    runtime_root: Path,
) -> None:
    address = ipaddress.ip_address(public_ip)
    if address.version != 4:
        raise RenderError("public address must be IPv4")
    runtime, node = _load_json(values_path), _load_json(node_path)
    xray, hysteria = _validated_values(runtime, node)
    masquerade = _read_regular(deploy_root / "masquerade" / "index.html").decode("utf-8")
    caddyfile = _read_regular(deploy_root / "caddy" / "Caddyfile")
    compose = _read_regular(deploy_root / "compose.yaml", maximum=512 * 1024)

    _atomic_write(etc_root / "control.toml", _control_config(str(address), xray).encode(), 0o640)
    _atomic_write(etc_root / "Caddyfile", caddyfile, 0o640)
    _atomic_write(etc_root / "compose.yaml", compose, 0o640)
    _atomic_write(runtime_root / "xray" / "config.json", _xray_config(xray).encode(), 0o600)
    _atomic_write(
        runtime_root / "hysteria" / "config.yaml",
        _hysteria_config(hysteria, masquerade).encode(),
        0o600,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Render server configuration")
    parser.add_argument("--values", required=True, type=Path)
    parser.add_argument("--node", required=True, type=Path)
    parser.add_argument("--public-ip", required=True)
    parser.add_argument("--deploy-root", required=True, type=Path)
    parser.add_argument("--etc-root", required=True, type=Path)
    parser.add_argument("--runtime-root", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        render(
            values_path=arguments.values,
            node_path=arguments.node,
            public_ip=arguments.public_ip,
            deploy_root=arguments.deploy_root,
            etc_root=arguments.etc_root,
            runtime_root=arguments.runtime_root,
        )
    except (RenderError, OSError, ValueError):
        print("Server configuration could not be rendered.", file=os.sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
