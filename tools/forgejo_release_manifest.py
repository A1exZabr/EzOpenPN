from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

IMAGE_NAMES = ("control", "xray", "cert-sync", "gateway")
SOURCE_PATTERN = re.compile(r"[0-9a-f]{40}")
DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
FORGEJO_ROOT = "git.alexzabrodin.pro/alex"


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--forgejo-digests", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    arguments = parse_arguments()
    if SOURCE_PATTERN.fullmatch(arguments.source_commit) is None:
        raise SystemExit("invalid source commit")
    if not arguments.input.is_file() or arguments.input.is_symlink():
        raise SystemExit("image manifest is not a regular file")
    if not arguments.forgejo_digests.is_file() or arguments.forgejo_digests.is_symlink():
        raise SystemExit("Forgejo digest map is not a regular file")

    source_manifest = json.loads(arguments.input.read_text(encoding="utf-8"))
    source = source_manifest.get("source")
    if not isinstance(source, dict) or source.get("commit") != arguments.source_commit:
        raise SystemExit("image manifest source does not match release source")
    images = source_manifest.get("images")
    if not isinstance(images, list):
        raise SystemExit("image manifest is invalid")
    by_name = {
        item.get("name"): item
        for item in images
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }
    if set(by_name) != set(IMAGE_NAMES):
        raise SystemExit("image manifest is incomplete")
    forgejo_digests = json.loads(arguments.forgejo_digests.read_text(encoding="utf-8"))
    if not isinstance(forgejo_digests, dict) or set(forgejo_digests) != set(IMAGE_NAMES):
        raise SystemExit("Forgejo digest map is incomplete")

    release_images = []
    for name in IMAGE_NAMES:
        source_digest = by_name[name].get("digest")
        digest = forgejo_digests[name]
        if (
            not isinstance(source_digest, str)
            or DIGEST_PATTERN.fullmatch(source_digest) is None
            or not isinstance(digest, str)
            or DIGEST_PATTERN.fullmatch(digest) is None
        ):
            raise SystemExit("image digest is invalid")
        release_images.append(
            {
                "name": name,
                "reference": f"{FORGEJO_ROOT}/ezopenpn-{name}",
                "digest": digest,
            }
        )

    result = {
        "schema": 1,
        "source": {
            "commit": arguments.source_commit,
            "repository": "A1exZabr/EzOpenPN",
        },
        "images": release_images,
    }
    arguments.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
