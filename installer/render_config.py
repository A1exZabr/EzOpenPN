from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
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
_KEY_PATTERN = re.compile(r"[A-Za-z0-9_-]{42,44}")
_SHORT_ID_PATTERN = re.compile(r"[0-9a-f]{16}")
_XRAY_FIELDS = frozenset(
    {"private_key", "short_id", "fallback_upload", "fallback_download"}
)
_NODE_FIELDS = frozenset({"xray_public_key", "xray_short_id"})
# Material created before v0.2.0 also names an external Reality target and an
# XHTTP path. They stay on disk so a rollback can still use them, and are
# ignored by this release.
_LEGACY_FIELDS = frozenset({"target", "server_name", "xhttp_path"})
# Reality hands every connection that is not ours to the gateway stub site.
_REALITY_TARGET = "gateway:8443"
_STUB_OPEN = "respond <<STUB"
_STUB_CLOSE = "STUB 200"
_STUB_NAMES = (
    ("Quiet", "Northern", "Silver", "Open", "Bright", "Green", "Calm", "Little"),
    ("Studio", "Workshop", "Notes", "Garden", "Field", "Corner", "Atlas", "Bench"),
)
_STUB_MESSAGES = (
    "New content is coming soon.",
    "This site is being prepared.",
    "Something new is on the way.",
    "The page will be available soon.",
)
_STUB_COLORS = (
    ("#f6f7f9", "#1f2933", "#2b6cb0"),
    ("#fbfaf7", "#2d2a26", "#8a5a2b"),
    ("#f4f8f5", "#1e2b24", "#2f7d4f"),
    ("#f7f6fb", "#26233a", "#5b4bb7"),
    ("#ffffff", "#222222", "#b03a2e"),
    ("#f5f7fa", "#1b2430", "#0f766e"),
)


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


def _require_fields(value: dict[str, Any], required: frozenset[str], label: str) -> None:
    present = set(value)
    if not required <= present or not present - required <= _LEGACY_FIELDS:
        raise RenderError(f"{label} has unexpected fields")


def _validated_values(
    runtime: dict[str, Any], node: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    if set(runtime) != {"xray", "hysteria"}:
        raise RenderError("runtime material has unexpected fields")
    xray_value = runtime["xray"]
    hysteria_value = runtime["hysteria"]
    if not isinstance(xray_value, dict) or not isinstance(hysteria_value, dict):
        raise RenderError("runtime material is invalid")
    _require_fields(xray_value, _XRAY_FIELDS, "Xray material")
    if set(hysteria_value) != {
        "certificate_path",
        "private_key_path",
        "obfs_password",
        "stats_secret",
    }:
        raise RenderError("Hysteria2 material has unexpected fields")
    _require_fields(node, _NODE_FIELDS, "node material")
    for name in _LEGACY_FIELDS:
        if xray_value.get(name) != node.get(name):
            raise RenderError("node and runtime material do not match")

    short_id = _string(xray_value["short_id"], "short ID")
    if _SHORT_ID_PATTERN.fullmatch(short_id) is None:
        raise RenderError("short ID is invalid")
    if node["xray_short_id"] != short_id:
        raise RenderError("node and runtime material do not match")
    upload = _limits(xray_value["fallback_upload"], "upload fallback")
    download = _limits(xray_value["fallback_download"], "download fallback")
    if upload == download:
        raise RenderError("fallback limits must differ")

    xray = {
        "private_key": _key(xray_value["private_key"], "private key"),
        "public_key": _key(node["xray_public_key"], "public key"),
        "short_id": short_id,
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


def stub_page(private_key: str) -> str:
    """Return the neutral page shown to anyone who is not a client.

    The wording and colours are derived from the node key, so the page stays
    the same across updates but differs between servers.
    """
    key = base64.urlsafe_b64decode(private_key + "=" * (-len(private_key) % 4))
    seed = hmac.new(key, b"ezopenpn stub page v1", hashlib.sha256).digest()
    name = f"{_STUB_NAMES[0][seed[0] % 8]} {_STUB_NAMES[1][seed[1] % 8]}"
    message = _STUB_MESSAGES[seed[2] % len(_STUB_MESSAGES)]
    background, text, accent = _STUB_COLORS[seed[3] % len(_STUB_COLORS)]
    body_style = (
        "margin:0;min-height:100vh;display:flex;align-items:center;"
        "justify-content:center;font-family:system-ui,-apple-system,"
        f"'Segoe UI',Roboto,sans-serif;background:{background};color:{text}"
    )
    return "\n".join(
        (
            "<!doctype html>",
            '<html lang="en">',
            "<head>",
            '<meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            f"<title>{name}</title>",
            "</head>",
            f'<body style="{body_style}">',
            '<main style="max-width:32rem;padding:2rem;text-align:center">',
            f'<h1 style="margin:0 0 0.75rem;font-size:2rem;color:{accent}">{name}</h1>',
            f'<p style="margin:0;font-size:1.05rem;line-height:1.6">{message}</p>',
            "</main>",
            "</body>",
            "</html>",
            "",
        )
    )


def _gateway_config(template: str, page: str) -> str:
    # Caddy would read braces in the page as placeholders.
    if any(character in page for character in "{}") or "STUB" in page:
        raise RenderError("stub page is invalid")
    lines = template.split("\n")
    opening = [index for index, line in enumerate(lines) if line.strip() == _STUB_OPEN]
    closing = [index for index, line in enumerate(lines) if line.strip() == _STUB_CLOSE]
    if len(opening) != 1 or len(closing) != 1 or closing[0] <= opening[0]:
        raise RenderError("gateway template is invalid")
    marker = lines[closing[0]]
    indent = marker[: len(marker) - len(marker.lstrip("\t"))]
    body = [f"{indent}{line}" for line in page.rstrip("\n").split("\n")]
    return "\n".join([*lines[: opening[0] + 1], *body, *lines[closing[0] :]])


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
                    "network": "raw",
                    "security": "reality",
                    "realitySettings": {
                        "show": False,
                        "target": _REALITY_TARGET,
                        "xver": 0,
                        # An empty name accepts clients that send no SNI, as
                        # browsers do when they open a bare IP address.
                        "serverNames": [""],
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
            f"reality_short_id = {_quote(values['short_id'])}",
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
    masquerade = stub_page(xray["private_key"])
    try:
        template = _read_regular(deploy_root / "caddy" / "Caddyfile").decode("utf-8")
    except UnicodeDecodeError:
        raise RenderError("gateway template is invalid") from None
    caddyfile = _gateway_config(template, masquerade).encode("utf-8")
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
