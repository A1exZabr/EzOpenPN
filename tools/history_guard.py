from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any, NoReturn

from content_guard import (
    _PROHIBITED_TYPOGRAPHY,
    _contains_prohibited_content,
    _contains_secret,
)

_OBJECT_ID = re.compile(r"^[0-9a-f]{40}$")


class HistoryGuardError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class HistoryFinding:
    kind: str
    object_id: str
    path_sha256: str | None
    safe_location: str


@dataclass(frozen=True, slots=True)
class HistoryScan:
    ok: bool
    findings: tuple[HistoryFinding, ...]
    objects_scanned: int
    commits_scanned: int
    blobs_scanned: int
    tags_scanned: int
    root_commits: int


def _fail(code: str) -> NoReturn:
    raise HistoryGuardError(code)


def _run_git(repository: Path, *arguments: str) -> bytes:
    try:
        result = subprocess.run(
            ["git", *arguments],
            cwd=repository,
            check=False,
            capture_output=True,
        )
    except OSError:
        _fail("git_unavailable")
    if result.returncode != 0:
        _fail("git_command_failed")
    return result.stdout


def _decode_text(raw: bytes) -> str | None:
    if b"\x00" in raw:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _text_finding_kinds(value: str) -> tuple[str, ...]:
    kinds: list[str] = []
    if _contains_prohibited_content(value):
        kinds.append("prohibited_content")
    if any(character in value for character in _PROHIBITED_TYPOGRAPHY):
        kinds.append("prohibited_typography")
    if _contains_secret(value):
        kinds.append("possible_secret")
    return tuple(kinds)


def _path_finding_kinds(value: str) -> tuple[str, ...]:
    kinds: list[str] = []
    if _contains_prohibited_content(value):
        kinds.append("prohibited_path")
    if any(character in value for character in _PROHIBITED_TYPOGRAPHY):
        kinds.append("prohibited_path_typography")
    return tuple(kinds)


def _location(kind: str, identity: str) -> str:
    digest = hashlib.sha256(identity.encode("utf-8", errors="surrogatepass")).hexdigest()
    return f"{kind}:{digest[:12]}"


def _read_exact(stream: IO[Any], size: int) -> bytes:
    blocks: list[bytes] = []
    remaining = size
    while remaining:
        block = stream.read(remaining)
        if not isinstance(block, bytes) or not block:
            _fail("git_batch_truncated")
        blocks.append(block)
        remaining -= len(block)
    return b"".join(blocks)


def _object_ids(repository: Path) -> tuple[str, ...]:
    output = _run_git(repository, "rev-list", "--objects", "--all", "--no-object-names")
    identities = {line.decode("ascii") for line in output.splitlines() if line}
    refs = _run_git(repository, "for-each-ref", "--format=%(objectname)")
    identities.update(line.decode("ascii") for line in refs.splitlines() if line)
    if not identities or any(_OBJECT_ID.fullmatch(identity) is None for identity in identities):
        _fail("git_object_list_invalid")
    return tuple(sorted(identities))


def _scan_objects(
    repository: Path, identities: Sequence[str]
) -> tuple[list[HistoryFinding], int, int, int]:
    try:
        process = subprocess.Popen(
            ["git", "cat-file", "--batch"],
            cwd=repository,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        _fail("git_unavailable")
    if process.stdin is None or process.stdout is None:
        process.kill()
        _fail("git_batch_unavailable")

    findings: list[HistoryFinding] = []
    commits = 0
    blobs = 0
    tags = 0
    try:
        for requested in identities:
            process.stdin.write(requested.encode("ascii") + b"\n")
            process.stdin.flush()
            header = process.stdout.readline().decode("ascii", errors="strict").rstrip("\n")
            parts = header.split()
            if len(parts) != 3 or parts[0] != requested or not parts[2].isdigit():
                _fail("git_batch_header_invalid")
            object_type = parts[1]
            size = int(parts[2])
            body = _read_exact(process.stdout, size)
            if process.stdout.read(1) != b"\n":
                _fail("git_batch_separator_invalid")
            if object_type == "commit":
                commits += 1
            elif object_type == "blob":
                blobs += 1
            elif object_type == "tag":
                tags += 1
            elif object_type == "tree":
                continue
            else:
                _fail("git_object_type_invalid")
            text = _decode_text(body)
            if text is None:
                continue
            for finding_kind in _text_finding_kinds(text):
                findings.append(
                    HistoryFinding(
                        kind=finding_kind,
                        object_id=requested,
                        path_sha256=None,
                        safe_location=_location(object_type, requested),
                    )
                )
    finally:
        process.stdin.close()
        process.stdout.close()
        return_code = process.wait(timeout=10)
        if return_code != 0 and not findings:
            _fail("git_batch_failed")
    return findings, commits, blobs, tags


def _scan_paths_and_refs(repository: Path, head: str) -> list[HistoryFinding]:
    findings: list[HistoryFinding] = []
    paths = _run_git(repository, "log", "--all", "--format=", "--name-only", "-z")
    for raw_path in paths.split(b"\x00"):
        if not raw_path or raw_path == b"\n":
            continue
        path_text = raw_path.decode("utf-8", errors="ignore").lstrip("\n")
        if not path_text:
            continue
        path_digest = hashlib.sha256(raw_path).hexdigest()
        for finding_kind in _path_finding_kinds(path_text):
            findings.append(
                HistoryFinding(
                    kind=finding_kind,
                    object_id=head,
                    path_sha256=path_digest,
                    safe_location=f"path:{path_digest[:12]}",
                )
            )

    refs = _run_git(repository, "for-each-ref", "--format=%(refname)%00%(objectname)")
    for line in refs.splitlines():
        try:
            raw_ref, raw_identity = line.split(b"\x00", 1)
            identity = raw_identity.decode("ascii")
        except (ValueError, UnicodeDecodeError):
            _fail("git_ref_list_invalid")
        if _OBJECT_ID.fullmatch(identity) is None:
            _fail("git_ref_list_invalid")
        ref_text = raw_ref.decode("utf-8", errors="ignore")
        ref_digest = hashlib.sha256(raw_ref).hexdigest()
        for finding_kind in _path_finding_kinds(ref_text):
            findings.append(
                HistoryFinding(
                    kind="prohibited_ref"
                    if finding_kind == "prohibited_path"
                    else "prohibited_ref_typography",
                    object_id=identity,
                    path_sha256=ref_digest,
                    safe_location=f"ref:{ref_digest[:12]}",
                )
            )
    return findings


def scan_git_history(repository: Path) -> HistoryScan:
    root = repository.resolve(strict=True)
    discovered = _run_git(root, "rev-parse", "--show-toplevel").decode("utf-8").strip()
    if Path(discovered).resolve() != root:
        _fail("repository_root_required")
    head = _run_git(root, "rev-parse", "HEAD").decode("ascii").strip()
    if _OBJECT_ID.fullmatch(head) is None:
        _fail("git_head_invalid")
    roots = [
        line for line in _run_git(root, "rev-list", "--max-parents=0", "--all").splitlines() if line
    ]
    identities = _object_ids(root)
    findings, commits, blobs, tags = _scan_objects(root, identities)
    findings.extend(_scan_paths_and_refs(root, head))
    if len(roots) != 1:
        findings.append(
            HistoryFinding(
                kind="multiple_roots",
                object_id=head,
                path_sha256=None,
                safe_location="history:roots",
            )
        )
    unique = tuple(
        sorted(
            set(findings),
            key=lambda item: (
                item.kind,
                item.object_id,
                item.path_sha256 or "",
                item.safe_location,
            ),
        )
    )
    return HistoryScan(
        ok=not unique,
        findings=unique,
        objects_scanned=len(identities),
        commits_scanned=commits,
        blobs_scanned=blobs,
        tags_scanned=tags,
        root_commits=len(roots),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit every object reachable from Git refs")
    parser.add_argument("repository", nargs="?", default=Path.cwd(), type=Path)
    arguments = parser.parse_args()
    try:
        result = scan_git_history(arguments.repository)
    except (HistoryGuardError, OSError, UnicodeError) as error:
        print(json.dumps({"code": str(error), "ok": False}, sort_keys=True))
        return 2
    payload = {
        "blobs_scanned": result.blobs_scanned,
        "commits_scanned": result.commits_scanned,
        "findings": [
            {
                "kind": finding.kind,
                "location": finding.safe_location,
                "object": finding.object_id,
                "path_sha256": finding.path_sha256,
            }
            for finding in result.findings
        ],
        "objects_scanned": result.objects_scanned,
        "ok": result.ok,
        "root_commits": result.root_commits,
        "tags_scanned": result.tags_scanned,
    }
    print(json.dumps(payload, sort_keys=True))
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
