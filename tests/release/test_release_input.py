from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
from test_workflow_run import COMMIT, ROOT, run_metadata


@pytest.mark.parametrize("defect", [None, "expired", "duplicate", "wrong_commit", "failed_run"])
def test_release_input_selects_only_one_immutable_trusted_artifact(
    tmp_path: Path, defect: str | None
):
    artifact = {
        "id": 123,
        "name": f"images-release-{COMMIT}",
        "expired": False,
        "workflow_run": {"id": 12, "head_sha": COMMIT},
    }
    run = run_metadata()
    if defect == "expired":
        artifact["expired"] = True
    if defect == "wrong_commit":
        artifact["workflow_run"]["head_sha"] = "b" * 40
    if defect == "failed_run":
        run["conclusion"] = "failure"
    artifacts = [artifact, artifact] if defect == "duplicate" else [artifact]
    (tmp_path / "run.json").write_text(json.dumps(run), encoding="utf-8")
    (tmp_path / "artifacts.json").write_text(
        json.dumps([{"artifacts": artifacts}]), encoding="utf-8"
    )
    binary = tmp_path / "gh"
    binary.write_text(
        "#!/usr/bin/env python3\nimport os,sys\nfrom pathlib import Path\n"
        "root=Path(os.environ['INPUT_FIXTURE'])\n"
        "name='artifacts.json' if any(x.endswith('/artifacts') for x in sys.argv) "
        "else 'run.json'\nprint((root/name).read_text())\n",
        encoding="utf-8",
    )
    binary.chmod(0o755)
    result = subprocess.run(
        [
            "bash",
            str(ROOT / "tools/release_input.sh"),
            "images",
            "12",
            COMMIT,
            f"images-release-{COMMIT}",
            "images",
        ],
        env=os.environ
        | {"INPUT_FIXTURE": str(tmp_path), "PATH": f"{tmp_path}:{os.environ['PATH']}"},
        capture_output=True,
        text=True,
        check=False,
    )
    if defect is None:
        assert result.returncode == 0, result.stderr
        assert result.stdout == "images_artifact_id=123\nimages_run_attempt=2\n"
    else:
        assert result.returncode != 0
        assert "artifact_id=" not in result.stdout
