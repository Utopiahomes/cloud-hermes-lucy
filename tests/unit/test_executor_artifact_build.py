from __future__ import annotations

import json
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).parents[2]
AWS_DEPLOY = ROOT / "deploy" / "aws"


def _fake_project(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    for relative in (
        "src/lucy/contracts",
        "src/lucy/executors",
        "deploy/aws",
    ):
        (root / relative).mkdir(parents=True, exist_ok=True)
    (root / "src/lucy/__init__.py").write_text("__version__ = 'test'\n")
    (root / "src/lucy/py.typed").write_text("")
    (root / "src/lucy/contracts/__init__.py").write_text("VALUE = 1\n")
    (root / "src/lucy/executors/__init__.py").write_text("VALUE = 2\n")
    for name in (
        "lambda-requirements.lock",
        "build_executor_artifact.py",
        "build-executor-artifact.ps1",
    ):
        shutil.copy2(AWS_DEPLOY / name, root / "deploy/aws" / name)
    return root


def _build(root: Path, staging_name: str, output_name: str) -> dict[str, object]:
    staging = root / staging_name
    staging.mkdir()
    (staging / "dependency.py").write_text("DEPENDENCY = True\n")
    (staging / "bin").mkdir()
    (staging / "bin/generated-tool.exe").write_bytes(staging_name.encode())
    record = staging / "fake-1.0.dist-info/RECORD"
    record.parent.mkdir()
    record.write_text(
        f"../../bin/generated-tool.exe,sha256={staging_name},12\n"
        "dependency.py,sha256=stable,18\n"
        "fake-1.0.dist-info/RECORD,,\n"
    )
    output = root / "dist" / output_name
    subprocess.run(
        [
            sys.executable,
            str(AWS_DEPLOY / "build_executor_artifact.py"),
            "--project-root",
            str(root),
            "--staging",
            str(staging),
            "--output",
            str(output),
            "--source-commit",
            "a" * 40,
            "--source-state",
            "dirty-local-test",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(output.with_suffix(".zip.manifest.json").read_text())


def test_executor_zip_and_manifest_are_deterministic_and_source_bound(tmp_path: Path) -> None:
    root = _fake_project(tmp_path)
    first = _build(root, "staging-a", "first.zip")
    second = _build(root, "staging-b", "second.zip")

    assert (root / "dist/first.zip").read_bytes() == (root / "dist/second.zip").read_bytes()
    assert first["artifact_sha256_hex"] == second["artifact_sha256_hex"]
    assert first["source_tree_sha256"] == second["source_tree_sha256"]
    assert first["source_commit"] == "a" * 40
    assert first["source_state"] == "dirty-local-test"
    assert first["architecture"] == "linux-amd64"
    assert first["python_runtime"] == "python3.12"

    with zipfile.ZipFile(root / "dist/first.zip") as artifact:
        names = artifact.namelist()
        assert names == sorted(names)
        assert "lucy/contracts/__init__.py" in names
        assert "lucy/executors/__init__.py" in names
        assert "dependency.py" in names
        assert "bin/generated-tool.exe" not in names
        assert all(item.date_time == (2020, 1, 1, 0, 0, 0) for item in artifact.infolist())
        record = artifact.read("fake-1.0.dist-info/RECORD").decode()
        assert "generated-tool" not in record


def test_executor_manifest_changes_when_packaged_source_changes(tmp_path: Path) -> None:
    root = _fake_project(tmp_path)
    before = _build(root, "staging-a", "before.zip")
    (root / "src/lucy/executors/__init__.py").write_text("VALUE = 3\n")
    after = _build(root, "staging-b", "after.zip")
    assert before["source_tree_sha256"] != after["source_tree_sha256"]
    assert before["artifact_sha256_hex"] != after["artifact_sha256_hex"]


def test_release_builder_requires_hashes_and_a_clean_tree_by_default() -> None:
    script = (AWS_DEPLOY / "build-executor-artifact.ps1").read_text(encoding="utf-8")
    assert "--require-hashes" in script
    assert "Release artifacts require a clean committed source tree" in script
    assert "[switch]$AllowDirtyForLocalTest" in script

    lock = (AWS_DEPLOY / "lambda-requirements.lock").read_text(encoding="utf-8")
    requirements = [line for line in lock.splitlines() if line and not line.startswith(("#", " "))]
    hashes = [line for line in lock.splitlines() if "--hash=sha256:" in line]
    assert len(requirements) == len(hashes) == 15
