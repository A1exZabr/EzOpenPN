from __future__ import annotations

import os
from pathlib import Path

from starlette.testclient import TestClient

from ezopenpn.web.app import create_runtime_app


def _secret(path: Path, value: bytes) -> None:
    path.write_bytes(value)
    path.chmod(0o600)


def test_runtime_factory_loads_configuration_and_secret_files(
    tmp_path: Path, monkeypatch
) -> None:
    database = tmp_path / "state.db"
    master_key = tmp_path / "master-key"
    api_secret = tmp_path / "api-secret"
    obfs_secret = tmp_path / "obfs-secret"
    _secret(master_key, bytes(range(32)))
    _secret(api_secret, os.urandom(32))
    _secret(obfs_secret, os.urandom(32))
    config = tmp_path / "control.toml"
    config.write_text(
        "\n".join(
            (
                '[app]',
                'public_ip = "203.0.113.10"',
                '[database]',
                f'path = "{database}"',
                '[paths]',
                f'master_key_path = "{master_key}"',
                f'hysteria_api_path = "{api_secret}"',
                f'hysteria_obfs_path = "{obfs_secret}"',
                '[xray]',
                'reality_public_key = "public-key"',
                'reality_server_name = "www.example.org"',
                'reality_short_id = "a1b2c3d4e5f60708"',
                'xhttp_path = "/runtime-test"',
            )
        )
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("EZOPENPN_CONFIG_PATH", str(config))

    application = create_runtime_app()

    with TestClient(application, base_url="https://203.0.113.10:9443") as client:
        response = client.get("/health/live")
    assert response.status_code == 200
