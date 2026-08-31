from __future__ import annotations

import hashlib
from pathlib import Path

from tests.release.test_bundle import build_release


def test_two_builds_are_byte_identical(tmp_path: Path) -> None:
    first = build_release(tmp_path / "one") / "ezopenpn-bundle.tar.gz"
    second = build_release(tmp_path / "two") / "ezopenpn-bundle.tar.gz"
    assert hashlib.sha256(first.read_bytes()).digest() == hashlib.sha256(
        second.read_bytes()
    ).digest()
