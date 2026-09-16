"""Reject successful-looking release inputs from another workflow or source."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPOSITORY = "A1exZabr/EzOpenPN"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("metadata", type=Path)
    parser.add_argument(
        "--workflow",
        choices=("images", "vm-matrix", "evidence", "candidate-release", "release"),
        required=True,
    )
    parser.add_argument("--commit", required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--tag")
    args = parser.parse_args()
    try:
        run = json.loads(args.metadata.read_text(encoding="utf-8"))
        valid = (
            isinstance(run, dict)
            and re.fullmatch(r"[0-9a-f]{40}", args.commit) is not None
            and args.run_id > 0
            and run.get("id") == args.run_id
            and run.get("path") == f".github/workflows/{args.workflow}.yml"
            and run.get("head_sha") == args.commit
            and run.get("event") == "workflow_dispatch"
            and run.get("status") == "completed"
            and run.get("conclusion") == "success"
            and (run.get("repository") or {}).get("full_name") == REPOSITORY
            and (run.get("head_repository") or {}).get("full_name") == REPOSITORY
            and type(run.get("run_attempt")) is int
            and run["run_attempt"] > 0
            and (
                args.tag is None
                or (
                    re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", args.tag) is not None
                    and run.get("head_branch") == args.tag
                )
            )
        )
    except (OSError, ValueError, TypeError, AttributeError):
        valid = False
    if not valid:
        print("workflow run does not match the required successful source check", file=sys.stderr)
        return 1
    print(run["run_attempt"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
