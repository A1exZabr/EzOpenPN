from __future__ import annotations

import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE_COMMIT = "0123456789abcdef0123456789abcdef01234567"


def test_verified_manifest_is_retargeted_without_changing_digests(tmp_path: Path) -> None:
    source = tmp_path / "images.release.json"
    destination = tmp_path / "images.forgejo.json"
    images = []
    for index, name in enumerate(("control", "xray", "cert-sync", "gateway"), 1):
        digest = f"sha256:{index:064x}"
        images.append(
            {
                "name": name,
                "reference": f"ghcr.io/a1exzabr/ezopenpn-{name}",
                "digest": digest,
                "sbom_path": f"{name}.spdx.json",
            }
        )
    source.write_text(
        json.dumps(
            {
                "schema": 1,
                "source": {"commit": SOURCE_COMMIT, "repository": "A1exZabr/EzOpenPN"},
                "images": images,
            }
        ),
        encoding="utf-8",
    )

    subprocess.run(
        [
            "python3",
            "tools/forgejo_release_manifest.py",
            "--source-commit",
            SOURCE_COMMIT,
            "--input",
            str(source),
            "--output",
            str(destination),
        ],
        cwd=ROOT,
        check=True,
    )

    result = json.loads(destination.read_text(encoding="utf-8"))
    assert result["source"] == {
        "commit": SOURCE_COMMIT,
        "repository": "A1exZabr/EzOpenPN",
    }
    assert [image["name"] for image in result["images"]] == [
        "control",
        "xray",
        "cert-sync",
        "gateway",
    ]
    assert [image["digest"] for image in result["images"]] == [
        f"sha256:{index:064x}" for index in range(1, 5)
    ]
    assert [image["reference"] for image in result["images"]] == [
        "git.alexzabrodin.pro/alex/ezopenpn-control",
        "git.alexzabrodin.pro/alex/ezopenpn-xray",
        "git.alexzabrodin.pro/alex/ezopenpn-cert-sync",
        "git.alexzabrodin.pro/alex/ezopenpn-gateway",
    ]
