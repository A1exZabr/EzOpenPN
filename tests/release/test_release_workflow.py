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


@pytest.mark.parametrize("failure", ["none", "published", "stable", "promote"])
def test_github_promotion_checks_public_downloads_and_rolls_back_latest(tmp_path: Path, failure):
    workflow = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())
    step = next(
        step for step in workflow["jobs"]["publish"]["steps"] if step.get("id") == "promotion"
    )
    gh = tmp_path / "gh"
    gh.write_text(
        "#!/usr/bin/env python3\nimport json,os,sys\n"
        "args=sys.argv[1:]\n"
        "if args[:2]==['release','list']: print('v0.1.8')\n"
        "elif args[:2]==['release','edit']:\n"
        " with open(os.environ['PROMOTION_LOG'],'a') as f: f.write(json.dumps(args)+'\\n')\n"
        " if '--prerelease=false' in args and os.environ['FAILURE']=='promote':\n"
        "  raise SystemExit(1)\n"
        "else: raise SystemExit(2)\n"
    )
    gh.chmod(0o755)
    verifier = """
bash() {
  test "$1" = tools/verify_release.sh || return 2
  printf '%s\n' "$2" >> "$PROMOTION_LOG"
  test "$2" != "--$FAILURE"
}
"""
    log = tmp_path / "log"
    result = subprocess.run(
        ["bash", "-e", "-o", "pipefail", "-c", verifier + step["run"]],
        cwd=ROOT,
        env=os.environ
        | {
            "PATH": f"{tmp_path}:{os.environ['PATH']}",
            "PROMOTION_LOG": str(log),
            "FAILURE": failure,
            "RELEASE_TAG": "v0.1.10",
            "GITHUB_SHA": COMMIT,
            "EXPECTED_BUNDLE_SHA256": "b" * 64,
        },
        capture_output=True,
        text=True,
        check=False,
    )

    def edit(tag, *flags):
        return json.dumps(["release", "edit", tag, "--repo", "A1exZabr/EzOpenPN", *flags])

    expected = [edit("v0.1.10", "--draft=false", "--prerelease", "--latest=false"), "--published"]
    if failure != "published":
        expected.append(edit("v0.1.10", "--prerelease=false", "--latest"))
        if failure != "promote":
            expected.append("--stable")
        if failure in {"stable", "promote"}:
            expected += [
                edit("v0.1.10", "--prerelease", "--latest=false"),
                edit("v0.1.8", "--latest"),
            ]
    assert log.read_text().splitlines() == expected
    assert result.returncode == (0 if failure == "none" else 1), result.stderr


@pytest.mark.parametrize("prerelease", [True, False])
def test_release_reuses_preview_without_overwriting_its_assets(tmp_path: Path, prerelease):
    workflow = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())
    step = next(step for step in workflow["jobs"]["draft"]["steps"] if step.get("id") == "draft")
    gh = tmp_path / "gh"
    gh.write_text(
        "#!/usr/bin/env python3\nimport json,sys\n"
        "assert sys.argv[1:3]==['release','view']\n"
        f"print(json.dumps({{'isDraft':False,'isPrerelease':{prerelease!r},'tagName':'v0.1.10'}}))\n"
    )
    gh.chmod(0o755)
    result = subprocess.run(
        ["bash", "-e", "-o", "pipefail", "-c", step["run"]],
        cwd=ROOT,
        env=os.environ | {"PATH": f"{tmp_path}:{os.environ['PATH']}", "RELEASE_TAG": "v0.1.10"},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == (0 if prerelease else 1), result.stderr
