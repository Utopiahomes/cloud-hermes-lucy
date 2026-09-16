#!/usr/bin/env python3
"""
Canonical digest for the guest.answer@1.0 RC2 conformance bundle.

The rule is deliberately small enough to reimplement from this docstring alone, in any
language, without running this script — identical in shape to the Management Contract
bundle's digest rule, so both bundles are verified the same way.

    1. Enumerate every file in the bundle EXCEPT MANIFEST.json and DIGEST.txt.
       Paths are recorded relative to the bundle root, using forward slashes.
    2. Sort those paths ascending by UTF-8 byte order.
    3. For each file, take sha256 over its RAW BYTES, lowercase hex.
    4. Build a canonical listing: for each path in order, the line

           <64 lowercase hex chars><two spaces><relative path><LF>

       concatenated, encoded UTF-8. This is the same layout `sha256sum` prints, so the
       listing can be cross-checked with coreutils (`sha256sum --text` on Windows, since
       Windows' sha256sum defaults to a binary-mode '*' marker that Linux's does not).
    5. The bundle digest is sha256 over that listing's bytes, lowercase hex.

Line endings matter, because step 3 hashes raw bytes. Every text file in the bundle is
stored with LF endings and no BOM, and the shipped .gitattributes pins that on checkout.

Usage:
    compute_digest.py --write   regenerate MANIFEST.json and DIGEST.txt
    compute_digest.py --check   recompute and compare against what is recorded
"""
import hashlib
import json
import pathlib
import sys

BUNDLE = pathlib.Path(__file__).resolve().parent.parent
EXCLUDED = {"MANIFEST.json", "DIGEST.txt"}
CONTRACT_REVISION = "RC2"


def bundle_files():
    out = []
    for p in sorted(BUNDLE.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(BUNDLE).as_posix()
        if rel in EXCLUDED:
            continue
        if "__pycache__" in p.parts or ".git" in p.parts:
            continue
        out.append(rel)
    return sorted(out)


def file_digest(rel):
    return hashlib.sha256((BUNDLE / rel).read_bytes()).hexdigest()


def canonical_listing(entries):
    return "".join(f"{d}  {rel}\n" for rel, d in entries).encode("utf-8")


def compute():
    entries = [(rel, file_digest(rel)) for rel in bundle_files()]
    listing = canonical_listing(entries)
    return entries, hashlib.sha256(listing).hexdigest()


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "--check"
    entries, digest = compute()

    if mode == "--write":
        manifest = {
            "bundle": "stoin-business-guest-answer-v1-bundle",
            "contract": "Utopia Homes Business Contract guest.answer@1.0",
            "contract_revision": CONTRACT_REVISION,
            "schema_dialect": "https://json-schema.org/draft/2020-12/schema",
            "digest_algorithm": "sha256",
            "digest_rule": (
                "sha256 over the canonical listing of '<file sha256><two spaces><relative "
                "path><LF>' lines, files sorted ascending by UTF-8 byte order, MANIFEST.json "
                "and DIGEST.txt excluded, each file hashed over its raw bytes with LF endings."
            ),
            "bundle_digest": digest,
            "file_count": len(entries),
            "files": [{"path": rel, "sha256": d} for rel, d in entries],
        }
        (BUNDLE / "MANIFEST.json").write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="")
        (BUNDLE / "DIGEST.txt").write_text(digest + "\n", encoding="utf-8", newline="")
        print(f"bundle_digest sha256:{digest}")
        print(f"files hashed: {len(entries)}")
        return 0

    recorded_path = BUNDLE / "DIGEST.txt"
    if not recorded_path.exists():
        print("DIGEST.txt is absent; run with --write first", file=sys.stderr)
        return 2
    recorded = recorded_path.read_text(encoding="utf-8").strip()
    if recorded != digest:
        print("DIGEST MISMATCH", file=sys.stderr)
        print(f"  recorded:   {recorded}", file=sys.stderr)
        print(f"  recomputed: {digest}", file=sys.stderr)
        manifest = json.loads((BUNDLE / "MANIFEST.json").read_text(encoding="utf-8"))
        was = {f["path"]: f["sha256"] for f in manifest["files"]}
        now = dict(entries)
        for rel in sorted(set(was) | set(now)):
            if was.get(rel) != now.get(rel):
                print(f"  changed: {rel}", file=sys.stderr)
        return 1
    print(f"bundle digest matches: sha256:{digest}")
    print(f"files hashed: {len(entries)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
