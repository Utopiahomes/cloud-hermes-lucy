"""Create a deterministic Lambda zip and a digest manifest from a staging tree."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import shutil
import zipfile
from pathlib import Path

FIXED_ZIP_TIME = (2020, 1, 1, 0, 0, 0)
SOURCE_PACKAGES = ("contracts", "executors")


def _remove_host_generated_console_scripts(staging: Path) -> None:
    """Remove target-path scripts whose launchers embed a random staging path."""
    scripts = staging / "bin"
    if scripts.exists():
        shutil.rmtree(scripts)
    for record in sorted(staging.glob("*.dist-info/RECORD")):
        rows = list(csv.reader(io.StringIO(record.read_text(encoding="utf-8"))))
        kept = [row for row in rows if row and not row[0].replace("\\", "/").startswith("../")]
        output = io.StringIO(newline="")
        csv.writer(output, lineterminator="\n").writerows(kept)
        record.write_text(output.getvalue(), encoding="utf-8", newline="\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--staging", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument(
        "--source-state", choices=("clean", "dirty-local-test"), default="clean"
    )
    arguments = parser.parse_args()

    root = arguments.project_root.resolve(strict=True)
    staging = arguments.staging.resolve(strict=True)
    output = arguments.output.resolve()
    if root not in output.parents:
        raise ValueError("artifact output must stay inside the project")
    output.parent.mkdir(parents=True, exist_ok=True)

    lucy_target = staging / "lucy"
    lucy_target.mkdir(exist_ok=True)
    shutil.copy2(root / "src" / "lucy" / "__init__.py", lucy_target / "__init__.py")
    shutil.copy2(root / "src" / "lucy" / "py.typed", lucy_target / "py.typed")
    for package in SOURCE_PACKAGES:
        shutil.copytree(
            root / "src" / "lucy" / package,
            lucy_target / package,
            dirs_exist_ok=True,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )

    _remove_host_generated_console_scripts(staging)

    files = sorted(
        path
        for path in staging.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"
    )
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for path in files:
            relative = path.relative_to(staging).as_posix()
            info = zipfile.ZipInfo(relative, FIXED_ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            zf.writestr(info, path.read_bytes(), compresslevel=9)

    artifact = output.read_bytes()
    digest = hashlib.sha256(artifact).digest()
    lock = (root / "deploy" / "aws" / "lambda-requirements.lock").read_bytes()
    source_digest = hashlib.sha256()
    source_files = [
        root / "src" / "lucy" / "__init__.py",
        root / "src" / "lucy" / "py.typed",
        root / "deploy" / "aws" / "lambda-requirements.lock",
        root / "deploy" / "aws" / "build_executor_artifact.py",
        root / "deploy" / "aws" / "build-executor-artifact.ps1",
    ]
    for package in SOURCE_PACKAGES:
        source_files.extend(
            path
            for path in (root / "src" / "lucy" / package).rglob("*")
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"
        )
    for path in sorted(set(source_files)):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        content = path.read_bytes()
        source_digest.update(relative)
        source_digest.update(b"\0")
        source_digest.update(len(content).to_bytes(8, "big"))
        source_digest.update(content)
    manifest = {
        "artifact": output.name,
        "artifact_bytes": len(artifact),
        "artifact_file_count": len(files),
        "artifact_sha256_base64": base64.b64encode(digest).decode("ascii"),
        "artifact_sha256_hex": digest.hex(),
        "architecture": "linux-amd64",
        "python_runtime": "python3.12",
        "requirements_lock_sha256": hashlib.sha256(lock).hexdigest(),
        "source_commit": arguments.source_commit,
        "source_state": arguments.source_state,
        "source_tree_sha256": source_digest.hexdigest(),
    }
    output.with_suffix(output.suffix + ".manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(json.dumps(manifest, sort_keys=True))


if __name__ == "__main__":
    main()
