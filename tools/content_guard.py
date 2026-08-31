from __future__ import annotations

import argparse
import hashlib
import os
import re
from collections.abc import Iterable
from pathlib import Path

PROHIBITED_CODEPOINTS = (
    (118, 112, 110),
    (1074, 1087, 1085),
)

LEGACY_HASHES = {
    7: {
        "9df9fbcc062eaeb4878c8e4070a910a3177af66901b7c026c792d5dbeed9b565",
        "bbace7c72de0ee8e3b0d4af9b1f88b79d7ac154e56dcca5f65855b37a48e07e5",
        "2be96eabe47efd9af4bdf5dc85c2264c1e5b3fc0d3b44e561953e6ebb7455745",
        "040ffd5925d40e11c67b7238a7fc9957850b8b9a46e9729fab88c24d6a98aff2",
    },
    8: {
        "4771e5a54bc39fe9ec290bdbf2a9c6fb6fe31d9a654c818690609d3c8e7bc735",
        "3f40462915a3e6026a4d790127b95ded4d870f6ab18d9af2fcbc454168255237",
        "44574c4ba2ea74ad4bf1e184133cdbf4e7390a3690beff6a7364511a70ec208e",
    },
    12: {"1e5c936639f3bcfd9720cb13071246e94999dfeeb3c8f1f82e9b01cdce3ae0c5"},
    20: {"0d98bc50af694fee7ba0dfd2f06dab35fcaa371202785b9bc004f914d9474dc2"},
}

_PROHIBITED_LABELS = tuple(
    "".join(chr(codepoint) for codepoint in codepoints).casefold()
    for codepoints in PROHIBITED_CODEPOINTS
)
_PROHIBITED_TYPOGRAPHY = frozenset({chr(0x2013), chr(0x2014)})
_SKIPPED_DIRECTORIES = frozenset(
    {
        ".git",
        ".worktrees",
        ".venv",
        ".pytest_cache",
        ".ruff_cache",
        ".mypy_cache",
        "__pycache__",
        "build",
        "dist",
        "node_modules",
    }
)
_SENSITIVE_ASSIGNMENT = re.compile(
    r"(?im)^\s*(?:password|token|secret|api[_-]?key)\s*[:=]\s*"
    r"(?P<quote>['\"])(?P<value>[^'\"\r\n]{12,})(?P=quote)\s*(?:[,;#]|$)"
)
_PRIVATE_KEY_MARKERS = (
    "-" * 5 + "BEGIN " + "PRIVATE" + " KEY" + "-" * 5,
    "-" * 5 + "BEGIN RSA " + "PRIVATE" + " KEY" + "-" * 5,
    "-" * 5 + "BEGIN EC " + "PRIVATE" + " KEY" + "-" * 5,
    "-" * 5 + "BEGIN OPENSSH " + "PRIVATE" + " KEY" + "-" * 5,
)


def _contains_hashed_legacy_fragment(value: str) -> bool:
    normalized = value.casefold()
    for length, expected_hashes in LEGACY_HASHES.items():
        if len(normalized) < length:
            continue
        for offset in range(len(normalized) - length + 1):
            fragment = normalized[offset : offset + length]
            digest = hashlib.sha256(fragment.encode("utf-8")).hexdigest()
            if digest in expected_hashes:
                return True
    return False


def _contains_prohibited_content(value: str) -> bool:
    normalized = value.casefold()
    return any(label in normalized for label in _PROHIBITED_LABELS) or (
        _contains_hashed_legacy_fragment(normalized)
    )


def _contains_secret(value: str) -> bool:
    return any(marker in value for marker in _PRIVATE_KEY_MARKERS) or bool(
        _SENSITIVE_ASSIGNMENT.search(value)
    )


def _iter_files(root: Path) -> Iterable[Path]:
    for current_root, directories, filenames in os.walk(root, followlinks=False):
        directories[:] = sorted(
            directory
            for directory in directories
            if directory not in _SKIPPED_DIRECTORIES
            and not (Path(current_root) / directory).is_symlink()
        )
        for filename in sorted(filenames):
            path = Path(current_root) / filename
            if not path.is_symlink():
                yield path


def scan_tree(root: Path) -> list[str]:
    root = root.resolve()
    diagnostics: list[str] = []
    for path in _iter_files(root):
        relative_path = path.relative_to(root).as_posix()
        raw = path.read_bytes()
        if b"\x00" in raw:
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue

        combined = f"{relative_path}\n{text}"
        if _contains_prohibited_content(combined):
            diagnostics.append(f"{relative_path}: prohibited content")
        if any(character in combined for character in _PROHIBITED_TYPOGRAPHY):
            diagnostics.append(f"{relative_path}: prohibited typography")
        if _contains_secret(text):
            diagnostics.append(f"{relative_path}: possible secret")

    return sorted(diagnostics)


def main() -> int:
    parser = argparse.ArgumentParser(description="Check repository text policy")
    parser.add_argument("root", nargs="?", default=".", type=Path)
    arguments = parser.parse_args()
    diagnostics = scan_tree(arguments.root)
    for diagnostic in diagnostics:
        print(diagnostic)
    return 1 if diagnostics else 0


if __name__ == "__main__":
    raise SystemExit(main())
