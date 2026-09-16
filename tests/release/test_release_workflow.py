from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
import yaml
from test_workflow_run import COMMIT, ROOT, run_metadata


@pytest.mark.parametrize("vm_passed", [True, False])
def test_real_release_selection_step_requires_successful_vm_run(tmp_path: Path, vm_passed: bool):
    tag = "v0.1.10"
    runs = {}
    artifacts = {}
    for identifier, workflow, names in (
        (12, "images", [f"images-release-{COMMIT}"]),
        (13, "vm-matrix", [f"vm-images-{COMMIT}"]),
        (14, "evidence", [f"release-evidence-{COMMIT}"]),
        (15, "candidate-release", [f"signed-candidate-{tag}", f"candidate-images-{tag}"]),
    ):
        runs[str(identifier)] = run_metadata() | {
            "id": identifier,
            "path": f".github/workflows/{workflow}.yml",
            "head_branch": tag,
            "conclusion": "failure" if identifier == 13 and not vm_passed else "success",
        }
        artifacts[str(identifier)] = [
            {
                "artifacts": [
                    {
                        "id": identifier * 10 + index,
                        "name": name,
                        "expired": False,
                        "workflow_run": {"id": identifier, "head_sha": COMMIT},
                    }
                    for index, name in enumerate(names)
                ]
            }
        ]
    (tmp_path / "api.json").write_text(json.dumps({"runs": runs, "artifacts": artifacts}))
    binary = tmp_path / "gh"
    binary.write_text(
        "#!/usr/bin/env python3\nimport json,os,sys\nfrom pathlib import Path\n"
        "data=json.loads(Path(os.environ['WORKFLOW_FIXTURE']).read_text())\n"
        "route=next(x for x in sys.argv if x.startswith('repos/')).split('/')\n"
        "kind='artifacts' if route[-1]=='artifacts' else 'runs'\n"
        "identifier=route[-2] if kind=='artifacts' else route[-1]\n"
        "print(json.dumps(data[kind][identifier]))\n",
    )
    binary.chmod(0o755)
    workflow = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())
    step = next(step for step in workflow["jobs"]["build"]["steps"] if step.get("id") == "inputs")
    output = tmp_path / "outputs"
    result = subprocess.run(
        ["bash", "-e", "-o", "pipefail", "-c", step["run"]],
        cwd=ROOT,
        env=os.environ
        | {
            "PATH": f"{tmp_path}:{os.environ['PATH']}",
            "GITHUB_SHA": COMMIT,
            "GITHUB_OUTPUT": str(output),
            "TAG": tag,
            "IMAGES_RUN_ID": "12",
            "VM_RUN_ID": "13",
            "EVIDENCE_RUN_ID": "14",
            "CANDIDATE_RUN_ID": "15",
            "WORKFLOW_FIXTURE": str(tmp_path / "api.json"),
        },
        capture_output=True,
        text=True,
        check=False,
    )
    if vm_passed:
        assert result.returncode == 0, result.stderr
        assert "candidate_artifact_id=150\n" in output.read_text()
    else:
        assert result.returncode != 0
        assert "candidate_artifact_id=" not in output.read_text()
    assert workflow["jobs"]["draft"]["needs"] == "build"
    assert "build" in workflow["jobs"]["publish"]["needs"]
