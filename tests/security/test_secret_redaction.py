from __future__ import annotations

import base64
import importlib.util
import json
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[2]


def _sanitizer() -> ModuleType:
    path = ROOT / "installer/sanitize_logs.py"
    specification = importlib.util.spec_from_file_location("ezopenpn_log_sanitizer", path)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def test_fixture_secrets_and_links_are_redacted(tmp_path: Path) -> None:
    first = ("fixture-profile-material-" + "a" * 16).encode()
    second = ("fixture-session-material-" + "b" * 16).encode()
    third = ("fixture-obfuscation-material-" + "c" * 16).encode()
    private_value = "fixture-private-material-" + "d" * 20
    short_value = "a1b2c3d4"
    paths = [tmp_path / name for name in ("master", "api", "obfs", "runtime.json")]
    for path, value in zip(paths[:3], (first, second, third), strict=True):
        path.write_bytes(value)
    paths[3].write_text(
        json.dumps(
            {
                "inbounds": [
                    {
                        "streamSettings": {
                            "realitySettings": {
                                "privateKey": private_value,
                                "shortIds": [short_value],
                            }
                        }
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    encoded = base64.urlsafe_b64encode(first).rstrip(b"=").decode("ascii")
    unsafe = " ".join(
        (
            first.decode(),
            second.decode(),
            third.decode(),
            encoded,
            private_value,
            short_value,
            "vless://fixture-value@example.test",
            "hysteria2://fixture-value@example.test",
            "token=fixture-value",
            "password=fixture-value",
        )
    )

    cleaned = _sanitizer().redact(unsafe, paths)

    for value in (
        first.decode(),
        second.decode(),
        third.decode(),
        encoded,
        private_value,
        short_value,
        "fixture-value@example.test",
    ):
        assert value not in cleaned
    assert cleaned.count("<redacted>") >= 8


def test_unknown_text_is_not_destroyed(tmp_path: Path) -> None:
    paths = [tmp_path / name for name in ("one", "two", "three", "runtime")]
    for path in paths:
        path.write_text("{}", encoding="utf-8")
    message = "control: service became healthy"

    assert _sanitizer().redact(message, paths) == message
