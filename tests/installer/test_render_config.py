from __future__ import annotations

import base64
import json
import stat
import tomllib
from pathlib import Path

import pytest
import yaml
from installer.render_config import RenderError, render, stub_page

_ROOT = Path(__file__).resolve().parents[2]


def _encoded(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


_PRIVATE_KEY = "UG2LfxKeyggwo4VTtVe2jycx85N1csWWomkiPdqE-nc"
_OTHER_PRIVATE_KEY = "wE2G6oGHFl38mixvBv_JGbju412yeuIyc140lRKiGGM"


def _material(*, legacy: bool = False) -> tuple[dict[str, object], dict[str, object]]:
    xray: dict[str, object] = {
        "private_key": _PRIVATE_KEY,
        "short_id": "a1b2c3d4e5f60708",
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
    }
    node: dict[str, object] = {
        "xray_public_key": "wE2G6oGHFl38mixvBv_JGbju412yeuIyc140lRKiGGM",
        "xray_short_id": "a1b2c3d4e5f60708",
    }
    if legacy:
        # Material written by v0.1.x for an external target and XHTTP.
        old_transport = {
            "target": "www.example.org:443",
            "server_name": "www.example.org",
            "xhttp_path": "/abcdefghijklmnopqrstuvwx",
        }
        xray.update(old_transport)
        node.update(old_transport)
    runtime = {
        "xray": xray,
        "hysteria": {
            "certificate_path": "/certs/fullchain.pem",
            "private_key_path": "/certs/privkey.pem",
            "obfs_password": _encoded(b"o" * 32),
            "stats_secret": _encoded(b"s" * 32),
        },
    }
    return runtime, node


def _prepare_paths(
    tmp_path: Path, *, legacy: bool = False
) -> tuple[Path, Path, Path, Path]:
    runtime, node = _material(legacy=legacy)
    tmp_path.mkdir(parents=True, exist_ok=True)
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


def _render(values_path: Path, node_path: Path, etc_root: Path, runtime_root: Path) -> None:
    render(
        values_path=values_path,
        node_path=node_path,
        public_ip="203.0.113.10",
        deploy_root=_ROOT / "deploy",
        etc_root=etc_root,
        runtime_root=runtime_root,
    )


def _outputs(etc_root: Path, runtime_root: Path) -> dict[str, bytes]:
    return {
        "control": (etc_root / "control.toml").read_bytes(),
        "caddy": (etc_root / "Caddyfile").read_bytes(),
        "compose": (etc_root / "compose.yaml").read_bytes(),
        "xray": (runtime_root / "xray" / "config.json").read_bytes(),
        "hysteria": (runtime_root / "hysteria" / "config.yaml").read_bytes(),
    }


def test_standalone_renderer_produces_selfsteal_configuration(tmp_path: Path) -> None:
    values_path, node_path, etc_root, runtime_root = _prepare_paths(tmp_path)

    _render(values_path, node_path, etc_root, runtime_root)

    control = tomllib.loads((etc_root / "control.toml").read_text(encoding="utf-8"))
    xray = json.loads((runtime_root / "xray" / "config.json").read_text(encoding="utf-8"))
    hysteria = yaml.safe_load(
        (runtime_root / "hysteria" / "config.yaml").read_text(encoding="utf-8")
    )
    caddyfile = (etc_root / "Caddyfile").read_text(encoding="utf-8")
    assert control["app"]["public_ip"] == "203.0.113.10"
    assert set(control["xray"]) == {
        "grpc_target",
        "inbound_tag",
        "reality_public_key",
        "reality_short_id",
    }
    stream = xray["inbounds"][0]["streamSettings"]
    assert stream["network"] == "raw"
    assert "xhttpSettings" not in stream
    assert stream["realitySettings"]["target"] == "gateway:8443"
    assert stream["realitySettings"]["serverNames"] == [""]
    assert xray["inbounds"][0]["settings"]["clients"] == []
    assert hysteria["auth"]["http"]["url"] == ("http://control:8000/internal/hysteria/auth")
    assert hysteria["tls"]["cert"] == "/certs/fullchain.pem"

    page = stub_page(_PRIVATE_KEY)
    assert hysteria["masquerade"]["string"]["content"] == page
    indented = "\n".join(f"\t\t\t{line}" for line in page.rstrip("\n").split("\n"))
    assert f"\t\trespond <<STUB\n{indented}\n\t\t\tSTUB 200\n" in caddyfile
    assert "<title>Welcome</title>" not in caddyfile
    assert "redir https://{host}{uri} 301" in caddyfile
    assert (etc_root / "compose.yaml").read_bytes() == (
        _ROOT / "deploy" / "compose.yaml"
    ).read_bytes()
    assert stat.S_IMODE((etc_root / "control.toml").stat().st_mode) == 0o640
    assert stat.S_IMODE((runtime_root / "xray" / "config.json").stat().st_mode) == 0o600


def test_material_from_earlier_releases_renders_the_same_configuration(
    tmp_path: Path,
) -> None:
    current = _prepare_paths(tmp_path / "current")
    legacy = _prepare_paths(tmp_path / "legacy", legacy=True)

    _render(*current)
    _render(*legacy)

    assert _outputs(current[2], current[3]) == _outputs(legacy[2], legacy[3])


def test_standalone_renderer_rejects_material_mismatch_without_outputs(
    tmp_path: Path,
) -> None:
    values_path, node_path, etc_root, runtime_root = _prepare_paths(tmp_path, legacy=True)
    node = json.loads(node_path.read_text(encoding="utf-8"))
    node["target"] = "other.example:443"
    node_path.write_text(json.dumps(node), encoding="utf-8")

    with pytest.raises(RenderError):
        _render(values_path, node_path, etc_root, runtime_root)

    assert not (etc_root / "control.toml").exists()
    assert not (runtime_root / "xray" / "config.json").exists()


def test_standalone_renderer_rejects_unknown_material_fields(tmp_path: Path) -> None:
    values_path, node_path, etc_root, runtime_root = _prepare_paths(tmp_path)
    runtime = json.loads(values_path.read_text(encoding="utf-8"))
    runtime["xray"]["dest"] = "www.example.org:443"
    values_path.write_text(json.dumps(runtime), encoding="utf-8")

    with pytest.raises(RenderError):
        _render(values_path, node_path, etc_root, runtime_root)

    assert not (etc_root / "Caddyfile").exists()


def test_stub_page_is_stable_per_server_and_differs_between_servers() -> None:
    page = stub_page(_PRIVATE_KEY)

    assert page == stub_page(_PRIVATE_KEY)
    assert page != stub_page(_OTHER_PRIVATE_KEY)
    assert page.startswith("<!doctype html>\n")
    # Braces would become Caddy placeholders; the product name is a fingerprint.
    assert not any(character in page for character in "{}")
    assert "ezopenpn" not in page.lower()


def test_gateway_template_needs_exactly_one_stub(tmp_path: Path) -> None:
    values_path, node_path, etc_root, runtime_root = _prepare_paths(tmp_path)
    deploy_root = tmp_path / "deploy"
    (deploy_root / "caddy").mkdir(parents=True)
    (deploy_root / "compose.yaml").write_bytes((_ROOT / "deploy" / "compose.yaml").read_bytes())
    template = (_ROOT / "deploy" / "caddy" / "Caddyfile").read_text(encoding="utf-8")
    (deploy_root / "caddy" / "Caddyfile").write_text(
        template.replace("respond <<STUB", "respond <<PAGE"), encoding="utf-8"
    )

    with pytest.raises(RenderError):
        render(
            values_path=values_path,
            node_path=node_path,
            public_ip="203.0.113.10",
            deploy_root=deploy_root,
            etc_root=etc_root,
            runtime_root=runtime_root,
        )
