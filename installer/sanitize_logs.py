#!/usr/bin/env python3
from __future__ import annotations

import base64
import json
import re
import sys
from pathlib import Path


def _stored_values(paths: list[Path]) -> set[str]:
    values: set[str] = set()
    for path in paths:
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        if not raw:
            continue
        values.add(base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii"))
        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if decoded:
            values.add(decoded)
    return values


def _runtime_values(path: Path) -> set[str]:
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
        reality = config["inbounds"][0]["streamSettings"]["realitySettings"]
        private_key = reality["privateKey"]
        short_ids = reality["shortIds"]
    except (OSError, KeyError, IndexError, TypeError, json.JSONDecodeError):
        return set()
    if not isinstance(private_key, str) or not isinstance(short_ids, list):
        return set()
    return {private_key, *(item for item in short_ids if isinstance(item, str))}


def redact(text: str, paths: list[Path]) -> str:
    values = _stored_values(paths[:3]) | _runtime_values(paths[3])
    for value in sorted(values, key=len, reverse=True):
        if value:
            text = text.replace(value, "<redacted>")
    text = re.sub(r"(?i)(?:vless|hysteria2)://[^\s]+", "<redacted>", text)
    return re.sub(
        r"(?i)(token|secret|password)=([^\s&]+)",
        r"\1=<redacted>",
        text,
    )


def main() -> int:
    if len(sys.argv) != 5:
        return 2
    paths = [Path(value) for value in sys.argv[1:]]
    sys.stdout.write(redact(sys.stdin.read(), paths))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
