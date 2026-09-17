#!/usr/bin/env python3
# ruff: noqa: E501, E701, E702
"""Compute the reproducible raw-content bundle digest.

Hash every file except MANIFEST.json and DIGEST.txt over raw bytes. Sort relative POSIX paths by
UTF-8 bytes. Hash the UTF-8 listing '<file sha256><two spaces><path><LF>'.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXCLUDED = {"MANIFEST.json", "DIGEST.txt"}

def compute() -> tuple[list[tuple[str, str]], str]:
    paths = sorted((p.relative_to(ROOT).as_posix() for p in ROOT.rglob("*") if p.is_file() and p.name not in EXCLUDED), key=lambda value: value.encode())
    entries = [(path, hashlib.sha256((ROOT / path).read_bytes()).hexdigest()) for path in paths]
    listing = "".join(f"{digest}  {path}\n" for path, digest in entries).encode()
    return entries, hashlib.sha256(listing).hexdigest()

def main() -> int:
    entries, digest = compute()
    if "--write" in sys.argv:
        manifest = {"bundle": "stoin-shared-model-execution-v1-rc1-bundle", "contract_digest": "a010c2cd5d501dd5586be3e1c54753ed7bf82505b9971d19c007e227bb9a75a8", "bundle_digest": digest, "file_count": len(entries), "files": [{"path": path, "sha256": value} for path, value in entries]}
        (ROOT / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
        (ROOT / "DIGEST.txt").write_text(digest + "\n", encoding="utf-8", newline="\n")
        print(f"sha256:{digest} ({len(entries)} files)")
        return 0
    recorded = (ROOT / "DIGEST.txt").read_text(encoding="utf-8").strip()
    if recorded != digest:
        print(f"digest mismatch: recorded={recorded} computed={digest}", file=sys.stderr); return 1
    print(f"bundle digest matches: sha256:{digest} ({len(entries)} files)"); return 0

if __name__ == "__main__": raise SystemExit(main())
