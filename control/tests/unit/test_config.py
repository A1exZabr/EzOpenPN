from pathlib import Path

import pytest
from pydantic import ValidationError

from ezopenpn.config import SecretFiles, Settings


def _write_protected(path: Path, value: bytes) -> None:
    path.write_bytes(value)
    path.chmod(0o600)


def test_settings_require_absolute_paths(tmp_path: Path) -> None:
    config = tmp_path / "control.toml"
    config.write_text(
        '[app]\npublic_ip="203.0.113.10"\ndatabase_path="relative.db"\n',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="database_path must be absolute"):
        Settings.load(config)


def test_settings_load_frozen_defaults(tmp_path: Path) -> None:
    config = tmp_path / "control.toml"
    config.write_text(
        '[app]\npublic_ip="203.0.113.10"\n'
        'database_path="/var/lib/ezopenpn/state.db"\n',
        encoding="utf-8",
    )

    settings = Settings.load(config)

    assert str(settings.public_ip) == "203.0.113.10"
    assert settings.database_path == Path("/var/lib/ezopenpn/state.db")
    assert settings.xray_grpc_target == "xray:10085"
    assert settings.session.idle_seconds == 12 * 60 * 60
    with pytest.raises(ValidationError, match="frozen"):
        settings.app.public_ip = "198.51.100.7"  # type: ignore[misc]


def test_secret_loader_rejects_open_permissions(tmp_path: Path) -> None:
    key = tmp_path / "master.key"
    key.write_bytes(bytes(range(32)))
    key.chmod(0o644)

    with pytest.raises(ValueError, match="0600"):
        SecretFiles.load(key, key, key)


def test_secret_loader_rejects_symbolic_links(tmp_path: Path) -> None:
    target = tmp_path / "target.bin"
    link = tmp_path / "linked.bin"
    _write_protected(target, bytes(range(32)))
    link.symlink_to(target)

    with pytest.raises(ValueError, match="symbolic link"):
        SecretFiles.load(link, target, target)


def test_secret_loader_rejects_wrong_length(tmp_path: Path) -> None:
    short = tmp_path / "short.bin"
    valid = tmp_path / "valid.bin"
    _write_protected(short, bytes(range(31)))
    _write_protected(valid, bytes(range(32)))

    with pytest.raises(ValueError, match="exactly 32 bytes"):
        SecretFiles.load(short, valid, valid)


def test_secret_values_are_redacted_from_repr(tmp_path: Path) -> None:
    master = tmp_path / "master.bin"
    api = tmp_path / "api.bin"
    obfs = tmp_path / "obfs.bin"
    _write_protected(master, b"m" * 32)
    _write_protected(api, b"a" * 32)
    _write_protected(obfs, b"o" * 32)

    loaded = SecretFiles.load(master, api, obfs)
    rendered = repr(loaded)

    assert loaded.master_key == b"m" * 32
    assert "mmmmmmmm" not in rendered
    assert "aaaaaaaa" not in rendered
    assert "oooooooo" not in rendered
    assert rendered.count("<redacted>") == 3
