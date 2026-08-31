from __future__ import annotations

import base64
import json
import stat
import tomllib
from pathlib import Path

import pytest
import yaml
from installer.render_config import RenderError, render

_ROOT = Path(__file__).resolve().parents[2]


def _encoded(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _material() -> tuple[dict[str, object], dict[str, object]]:
    runtime = {
        "xray": {
            "target": "www.example.org:443",
            "server_name": "www.example.org",
            "private_key": "UG2LfxKeyggwo4VTtVe2jycx85N1csWWomkiPdqE-nc",
            "short_id": "a1b2c3d4e5f60708",
            "xhttp_path": "/abcdefghijklmnopqrstuvwx",
            "fallback_upload": {
                "after_bytes": 9_437_184,
                "bytes_per_second": 786_432,
                "burst_bytes_per_second": 3_145_728,
            },
            "fallback_download": {
                "after_bytes": 11_534_336,
                "bytes_per_second": 1_048_576,
                "burst_bytes_per_second": 4_194_304,
            },
        },
        "hysteria": {
            "certificate_path": "/certs/fullchain.pem",
            "private_key_path": "/certs/privkey.pem",
            "obfs_password": _encoded(b"o" * 32),
            "stats_secret": _encoded(b"s" * 32),
        },
    }
    node = {
        "server_name": "www.example.org",
        "target": "www.example.org:443",
        "xhttp_path": "/abcdefghijklmnopqrstuvwx",
        "xray_public_key": "wE2G6oGHFl38mixvBv_JGbju412yeuIyc140lRKiGGM",
        "xray_short_id": "a1b2c3d4e5f60708",
    }
    return runtime, node


def _prepare_paths(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    runtime, node = _material()
    values_path = tmp_path / "runtime-values.json"
    node_path = tmp_path / "node.json"
    values_path.write_text(json.dumps(runtime), encoding="utf-8")
    node_path.write_text(json.dumps(node), encoding="utf-8")
    etc_root = tmp_path / "etc"
    runtime_root = tmp_path / "runtime"
    etc_root.mkdir()
    (runtime_root / "xray").mkdir(parents=True)
    (runtime_root / "hysteria").mkdir()
    return values_path, node_path, etc_root, runtime_root


def test_standalone_renderer_produces_complete_private_configuration(
    tmp_path: Path,
) -> None:
    values_path, node_path, etc_root, runtime_root = _prepare_paths(tmp_path)

    render(
        values_path=values_path,
        node_path=node_path,
        public_ip="203.0.113.10",
        deploy_root=_ROOT / "deploy",
        etc_root=etc_root,
        runtime_root=runtime_root,
    )

    control = tomllib.loads((etc_root / "control.toml").read_text(encoding="utf-8"))
    xray = json.loads((runtime_root / "xray" / "config.json").read_text(encoding="utf-8"))
    hysteria = yaml.safe_load(
        (runtime_root / "hysteria" / "config.yaml").read_text(encoding="utf-8")
    )
    assert control["app"]["public_ip"] == "203.0.113.10"
    assert control["xray"]["reality_server_name"] == "www.example.org"
    assert xray["inbounds"][0]["streamSettings"]["realitySettings"]["target"] == (
        "www.example.org:443"
    )
    assert hysteria["auth"]["http"]["url"] == ("http://control:8000/internal/hysteria/auth")
    assert hysteria["tls"]["cert"] == "/certs/fullchain.pem"
    assert (etc_root / "Caddyfile").read_bytes() == (
        _ROOT / "deploy" / "caddy" / "Caddyfile"
    ).read_bytes()
    assert (etc_root / "compose.yaml").read_bytes() == (
        _ROOT / "deploy" / "compose.yaml"
    ).read_bytes()
    assert stat.S_IMODE((etc_root / "control.toml").stat().st_mode) == 0o640
    assert stat.S_IMODE((runtime_root / "xray" / "config.json").stat().st_mode) == 0o600


def test_standalone_renderer_rejects_material_mismatch_without_outputs(
    tmp_path: Path,
) -> None:
    values_path, node_path, etc_root, runtime_root = _prepare_paths(tmp_path)
    node = json.loads(node_path.read_text(encoding="utf-8"))
    node["target"] = "other.example:443"
    node_path.write_text(json.dumps(node), encoding="utf-8")

    with pytest.raises(RenderError):
        render(
            values_path=values_path,
            node_path=node_path,
            public_ip="203.0.113.10",
            deploy_root=_ROOT / "deploy",
            etc_root=etc_root,
            runtime_root=runtime_root,
        )

    assert not (etc_root / "control.toml").exists()
    assert not (runtime_root / "xray" / "config.json").exists()
