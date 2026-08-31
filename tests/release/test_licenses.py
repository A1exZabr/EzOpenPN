from __future__ import annotations

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_original_project_license_is_neutral_mit() -> None:
    license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert "MIT License" in license_text
    assert "EzOpenPN contributors" in license_text
    assert "Copyright (c) 2026" in license_text


def test_every_distributed_upstream_image_has_notice() -> None:
    lock = tomllib.loads((ROOT / "deploy/images.lock").read_text(encoding="utf-8"))
    notices = (ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
    for image in lock["images"].values():
        assert image["repository"] in notices
        assert image["version"] in notices


def test_every_direct_python_dependency_has_notice() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    notices = (ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8").casefold()
    dependencies = project["project"]["dependencies"]
    for dependency in dependencies:
        package = re.split(r"[<>=!~\[]", dependency, maxsplit=1)[0].casefold()
        assert f"`{package}`" in notices


def test_xray_schemas_and_generated_derivatives_keep_mpl_marker() -> None:
    schema_files = sorted((ROOT / "proto/xray").rglob("*.proto"))
    generated_files = sorted(
        (ROOT / "control/src/ezopenpn/integrations/xray_proto").rglob("*.py")
    )
    assert schema_files and generated_files
    marker = "SPDX-" + "License-Identifier: MPL-2.0"
    for path in (*schema_files, *generated_files):
        assert marker in path.read_text(encoding="utf-8")
    assert (ROOT / "proto/xray/LICENSE").read_text(encoding="utf-8").startswith(
        "Mozilla Public License Version 2.0"
    )


def test_repository_policies_use_private_security_reporting() -> None:
    security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    contributing = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    assert "/security/advisories/new" in security
    assert "tools/content_guard.py" in contributing
    assert "секрет" in contributing.casefold()
