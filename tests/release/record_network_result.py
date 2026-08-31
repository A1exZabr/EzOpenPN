from __future__ import annotations

import argparse
import os
from contextlib import suppress
from pathlib import Path
from typing import NoReturn

from validate_evidence import (
    NETWORK_TYPES,
    canonical_json_bytes,
    load_json_document,
    validate_client_result,
    validate_network_result,
)


class EvidenceWriteError(RuntimeError):
    pass


def _fail(code: str) -> NoReturn:
    raise EvidenceWriteError(code)


def _write_canonical_document(value: object, output_path: Path) -> None:
    if output_path.suffix != ".json" or not output_path.parent.is_dir():
        _fail("output_path_invalid")

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(output_path, flags, 0o644)
    except OSError:
        _fail("output_exists_or_invalid")
    try:
        os.fchmod(descriptor, 0o644)
        pending = memoryview(canonical_json_bytes(value))
        while pending:
            written = os.write(descriptor, pending)
            if written <= 0:
                raise OSError("short evidence write")
            pending = pending[written:]
        os.fsync(descriptor)
    except OSError:
        with suppress(OSError):
            output_path.unlink(missing_ok=True)
        _fail("output_write_failed")
    finally:
        os.close(descriptor)


def write_network_result(input_path: Path, output_path: Path, expected_network_type: str) -> None:
    if expected_network_type not in NETWORK_TYPES:
        _fail("network_type_invalid")
    value, load_result = load_json_document(input_path, require_canonical=False)
    if not load_result.ok:
        _fail(load_result.code)
    validation = validate_network_result(value)
    if not validation.ok:
        _fail(validation.code)
    if not isinstance(value, dict) or value.get("network_type") != expected_network_type:
        _fail("network_type_mismatch")
    _write_canonical_document(value, output_path)


def write_client_result(input_path: Path, output_path: Path) -> None:
    value, load_result = load_json_document(input_path, require_canonical=False)
    if not load_result.ok:
        _fail(load_result.code)
    validation = validate_client_result(value)
    if not validation.ok:
        _fail(validation.code)
    _write_canonical_document(value, output_path)


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate and write sanitized evidence")
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    kind = parser.add_mutually_exclusive_group(required=True)
    kind.add_argument("--network-type", choices=NETWORK_TYPES)
    kind.add_argument("--clients", action="store_true")
    arguments = parser.parse_args()
    try:
        if arguments.clients:
            write_client_result(arguments.input, arguments.output)
        else:
            write_network_result(arguments.input, arguments.output, arguments.network_type)
    except EvidenceWriteError as error:
        print(f"record_failed:{error}")
        return 1
    print("recorded:ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
