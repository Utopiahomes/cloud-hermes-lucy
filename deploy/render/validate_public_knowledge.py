"""Validate and digest a Public Lucy knowledge candidate without staging it."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from lucy.publication import knowledge_snapshot, snapshot_digest


def validate_candidate(path: Path) -> tuple[int, str]:
    raw: Any = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or raw.get("schema") != "lucy-public-knowledge-v1":
        raise ValueError("candidate must use the lucy-public-knowledge-v1 schema")
    entries = raw.get("entries")
    if not isinstance(entries, list):
        raise ValueError("candidate entries must be a list")
    snapshot = knowledge_snapshot(entries)
    return len(snapshot["entries"]), snapshot_digest(snapshot)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate", type=Path)
    args = parser.parse_args()
    entry_count, digest = validate_candidate(args.candidate)
    print(
        json.dumps(
            {"schema": "lucy-public-knowledge-v1", "entries": entry_count, "sha256": digest}
        )
    )


if __name__ == "__main__":
    main()
