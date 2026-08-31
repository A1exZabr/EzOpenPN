from __future__ import annotations

import base64
import json
import secrets
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT))

from tools.render_runtime_config import render_runtime_configs  # noqa: E402

_XRAY_PRIVATE_KEY = "UG2LfxKeyggwo4VTtVe2jycx85N1csWWomkiPdqE-nc"
_XRAY_PUBLIC_KEY = "wE2G6oGHFl38mixvBv_JGbju412yeuIyc140lRKiGGM"


def _encoded(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _write(path: Path, content: str | bytes, mode: int) -> None:
    if isinstance(content, str):
        path.write_text(content, encoding="utf-8")
    else:
        path.write_bytes(content)
    path.chmod(mode)


def prepare(root: Path, state_path: Path, project: str) -> None:
    if not root.is_dir() or root.is_symlink() or state_path.exists():
        raise SystemExit("stack preparation paths are unsafe")
    directories = {
        "control": root / "control",
        "secrets": root / "secrets",
        "xray_run": root / "xray-run",
        "hysteria_certs": root / "hysteria-certs",
        "caddy_data": root / "caddy-data",
        "runtime": root / "runtime",
    }
    for directory in directories.values():
        directory.mkdir(mode=0o700)

    master_key = secrets.token_bytes(32)
    hysteria_api = secrets.token_bytes(32)
    hysteria_obfs = secrets.token_bytes(32)
    _write(directories["secrets"] / "master.key", master_key, 0o600)
    _write(directories["secrets"] / "hysteria-api.key", hysteria_api, 0o600)
    _write(directories["secrets"] / "hysteria-obfs.key", hysteria_obfs, 0o600)

    control = "\n".join(
        (
            "[app]",
            'public_ip = "127.0.0.1"',
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
            f'reality_public_key = "{_XRAY_PUBLIC_KEY}"',
            'reality_server_name = "www.example.org"',
            'reality_short_id = "a1b2c3d4e5f60708"',
            'xhttp_path = "/stack-check"',
            "",
            "[hysteria]",
            'stats_url = "http://hysteria:9999"',
            "",
        )
    )
    _write(root / "control.toml", control, 0o640)

    runtime_values = {
        "xray": {
            "target": "www.example.org:443",
            "server_name": "www.example.org",
            "private_key": _XRAY_PRIVATE_KEY,
            "short_id": "a1b2c3d4e5f60708",
            "xhttp_path": "/stack-check",
            "fallback_upload": {
                "after_bytes": 9437184,
                "bytes_per_second": 786432,
                "burst_bytes_per_second": 3145728,
            },
            "fallback_download": {
                "after_bytes": 11534336,
                "bytes_per_second": 1048576,
                "burst_bytes_per_second": 4194304,
            },
        },
        "hysteria": {
            "certificate_path": "/certs/fullchain.pem",
            "private_key_path": "/certs/privkey.pem",
            "obfs_password": _encoded(hysteria_obfs),
            "stats_secret": _encoded(hysteria_api),
        },
    }
    values_path = root / "runtime-values.json"
    _write(values_path, json.dumps(runtime_values), 0o600)
    render_runtime_configs(values_path, directories["runtime"])

    fixture_environment = (
        _ROOT / "tests" / "compose" / "fixtures" / "stack.env"
    ).read_text(encoding="utf-8")
    environment = fixture_environment.replace(
        "PUBLIC_IP=203.0.113.10", "PUBLIC_IP=127.0.0.1"
    )
    environment += f"STACK_TEST_ROOT={root}\n"
    environment += f"REPOSITORY_ROOT={_ROOT}\n"
    environment_path = root / "stack.env"
    _write(environment_path, environment, 0o600)

    state = {
        "root": str(root),
        "project": project,
        "environment_file": str(environment_path),
    }
    _write(state_path, json.dumps(state, sort_keys=True), 0o600)


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit("usage: stack_prepare.py ROOT STATE PROJECT")
    prepare(Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3])
