from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest
from test_bundle import ROOT, SOURCE_COMMIT, build_release


@pytest.mark.parametrize(
    "defect", [None, "old_version", "changed_installer", "wrong_bundle", "prerelease", "draft"]
)
def test_stable_channel_requires_the_verified_version_and_bootstrap(tmp_path: Path, defect):
    release = build_release(tmp_path / "release")
    for name in ("ezopenpn-bundle.sigstore.json", "SHA256SUMS.sigstore.json"):
        (release / name).write_text("{}", encoding="utf-8")
    (release / "ezopenpn-bundle.spdx.json").write_text('{"spdxVersion":"SPDX-2.3"}')
    (tmp_path / "version").write_text(
        json.dumps(
            {
                "tag_name": "v0.0.9" if defect == "old_version" else "v0.1.0",
                "draft": defect == "draft",
                "prerelease": defect == "prerelease",
            }
        )
    )
    (tmp_path / "install.sh").write_bytes(
        b"changed" if defect == "changed_installer" else (release / "install.sh").read_bytes()
    )
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "cosign").write_text("#!/bin/sh\nexit 0\n")
    (bin_dir / "curl").write_text(
        "#!/usr/bin/env python3\nimport os,sys\nfrom pathlib import Path\n"
        "from urllib.parse import urlsplit\n"
        "args=sys.argv[1:]; root=Path(os.environ['CHANNEL_FIXTURE'])\n"
        "url=next(x for x in args if x.startswith('https://')); path=urlsplit(url).path\n"
        "if url.startswith('https://github.com/A1exZabr/EzOpenPN/releases/download/v0.1.0/'):\n"
        " source=root/'release'/path.rsplit('/',1)[1]\n"
        "elif url=='https://api.github.com/repos/A1exZabr/EzOpenPN/releases/latest':\n"
        " source=root/'version'\n"
        "elif url=='https://github.com/A1exZabr/EzOpenPN/releases/latest/download/install.sh':\n"
        " source=root/'install.sh'\n"
        "else: raise SystemExit(22)\n"
        "Path(args[args.index('-o')+1]).write_bytes(source.read_bytes())\n",
        encoding="utf-8",
    )
    for path in bin_dir.iterdir():
        path.chmod(0o755)
    expected_digest = (
        "b" * 64
        if defect == "wrong_bundle"
        else hashlib.sha256((release / "ezopenpn-bundle.tar.gz").read_bytes()).hexdigest()
    )
    result = subprocess.run(
        [
            "bash",
            str(ROOT / "tools/verify_release.sh"),
            "--stable",
            "v0.1.0",
            SOURCE_COMMIT,
            expected_digest,
        ],
        env=os.environ
        | {"CHANNEL_FIXTURE": str(tmp_path), "PATH": f"{bin_dir}:{os.environ['PATH']}"},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == (0 if defect is None else 1), result.stdout + result.stderr
    if defect is None:
        assert "Stable installation channel v0.1.0 verified" in result.stdout
