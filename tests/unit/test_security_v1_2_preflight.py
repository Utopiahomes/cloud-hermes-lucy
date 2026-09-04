from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
import sys
import zipfile
from pathlib import Path
from types import ModuleType
from typing import Any

ROOT = Path(__file__).parents[2]


def _preflight() -> ModuleType:
    path = ROOT / "deploy" / "aws" / "preflight_security_v1_2.py"
    spec = importlib.util.spec_from_file_location("preflight_security_v1_2", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _artifact(tmp_path: Path) -> tuple[Path, Path, dict[str, Any]]:
    artifact = tmp_path / "executors.zip"
    with zipfile.ZipFile(artifact, "w") as archive:
        archive.writestr("lucy/executors/handlers.py", "VALUE = 1\n")
        archive.writestr("lucy/contracts/security_v1_2.py", "VALUE = 2\n")
    content = artifact.read_bytes()
    digest = hashlib.sha256(content).digest()
    manifest = {
        "artifact_bytes": len(content),
        "artifact_file_count": 2,
        "artifact_sha256_base64": base64.b64encode(digest).decode("ascii"),
        "artifact_sha256_hex": digest.hex(),
        "architecture": "linux-amd64",
        "python_runtime": "python3.12",
        "source_state": "clean",
    }
    manifest_path = tmp_path / "executors.zip.manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    return artifact, manifest_path, manifest


def test_local_release_artifact_passes_every_check(tmp_path: Path) -> None:
    module = _preflight()
    artifact, manifest_path, _ = _artifact(tmp_path)
    checks, _ = module.verify_local_artifact(artifact, manifest_path)
    assert checks
    assert all(check.passed for check in checks)


def test_tampered_local_release_artifact_fails_digest_and_size(tmp_path: Path) -> None:
    module = _preflight()
    artifact, manifest_path, _ = _artifact(tmp_path)
    with artifact.open("ab") as handle:
        handle.write(b"tamper")
    checks, _ = module.verify_local_artifact(artifact, manifest_path)
    failed = {check.name for check in checks if not check.passed}
    assert {"artifact.sha256_hex", "artifact.sha256_base64", "artifact.size"} <= failed


def test_preflight_requires_the_exact_sso_admin_and_account() -> None:
    module = _preflight()
    valid = module.verify_caller(
        {
            "Account": "123456789012",
            "Arn": (
                "arn:aws:sts::123456789012:assumed-role/"
                "AWSReservedSSO_LucySecurityAdministrator_abc123/owner"
            ),
        },
        "123456789012",
    )
    assert all(check.passed for check in valid)
    root = module.verify_caller(
        {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:root"},
        "123456789012",
    )
    assert not all(check.passed for check in root)


def test_preflight_waits_until_lambda_has_thirteen_unreserved() -> None:
    module = _preflight()
    held = module.verify_lambda_quota(
        {"AccountLimit": {"ConcurrentExecutions": 10, "UnreservedConcurrentExecutions": 10}}
    )
    ready = module.verify_lambda_quota(
        {
            "AccountLimit": {
                "ConcurrentExecutions": 1000,
                "UnreservedConcurrentExecutions": 1000,
            }
        }
    )
    assert held[0].passed is False
    assert ready[0].passed is True


def test_preflight_binds_render_oidc_to_exact_workspace_and_audience() -> None:
    module = _preflight()
    account = "123456789012"
    workspace = "tea-example"
    arn = f"arn:aws:iam::{account}:oidc-provider/oidc.render.com/{workspace}"
    checks = module.verify_render_oidc(
        {
            "Url": f"oidc.render.com/{workspace}",
            "ClientIDList": ["sts.amazonaws.com"],
            "ThumbprintList": ["a" * 40],
        },
        workspace_id=workspace,
        provider_arn=arn,
        account_id=account,
    )
    assert all(check.passed for check in checks)


def test_preflight_streams_and_hashes_exact_s3_object(tmp_path: Path) -> None:
    module = _preflight()
    artifact, _, manifest = _artifact(tmp_path)
    response = {
        "Body": io.BytesIO(artifact.read_bytes()),
        "ContentLength": artifact.stat().st_size,
        "ServerSideEncryption": "AES256",
        "VersionId": "exact-version",
    }
    checks = module.verify_s3_artifact(
        response, expected_version="exact-version", manifest=manifest
    )
    assert all(check.passed for check in checks)


def test_preflight_rejects_wrong_s3_version_even_when_bytes_match(tmp_path: Path) -> None:
    module = _preflight()
    artifact, _, manifest = _artifact(tmp_path)
    response = {
        "Body": io.BytesIO(artifact.read_bytes()),
        "ContentLength": artifact.stat().st_size,
        "ServerSideEncryption": "AES256",
        "VersionId": "another-version",
    }
    checks = module.verify_s3_artifact(
        response, expected_version="exact-version", manifest=manifest
    )
    assert {check.name for check in checks if not check.passed} == {"aws.artifact_version"}
