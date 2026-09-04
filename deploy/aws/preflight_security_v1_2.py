"""Fail-closed, read-only preflight for Security Baseline v1.2 deployment.

The command accepts only public deployment identifiers and a local release
artifact/manifest. It never reads or writes application secrets or transcript
data, and it performs no AWS mutation.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
import zipfile
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any

import boto3  # type: ignore[import-untyped]

_ACCOUNT_ID = re.compile(r"[0-9]{12}\Z")
_WORKSPACE_ID = re.compile(r"tea-[A-Za-z0-9_-]+\Z")
_ADMIN_SESSION = re.compile(
    r"arn:aws:sts::(?P<account>[0-9]{12}):assumed-role/"
    r"AWSReservedSSO_LucySecurityAdministrator_[A-Za-z0-9]+/[^/]+\Z"
)


@dataclass(frozen=True)
class Check:
    name: str
    passed: bool
    detail: str


def verify_local_artifact(
    artifact: Path, manifest_path: Path
) -> tuple[list[Check], dict[str, Any]]:
    """Verify an exact clean Linux AMD64 release artifact without executing it."""
    try:
        manifest_raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [Check("artifact.manifest", False, f"unreadable manifest: {type(exc).__name__}")], {}
    if not isinstance(manifest_raw, dict):
        return [Check("artifact.manifest", False, "manifest root must be an object")], {}
    manifest: dict[str, Any] = manifest_raw
    try:
        content = artifact.read_bytes()
    except OSError as exc:
        check = Check("artifact.file", False, f"unreadable artifact: {type(exc).__name__}")
        return [check], manifest

    digest = hashlib.sha256(content).digest()
    try:
        with zipfile.ZipFile(artifact) as archive:
            file_count = len(archive.infolist())
            bad_paths = [
                item.filename
                for item in archive.infolist()
                if (candidate := PurePosixPath(item.filename.replace("\\", "/"))).is_absolute()
                or ".." in candidate.parts
                or re.match(r"^[A-Za-z]:", item.filename) is not None
            ]
    except (OSError, zipfile.BadZipFile):
        file_count = -1
        bad_paths = ["invalid-zip"]

    expected_hex = manifest.get("artifact_sha256_hex")
    expected_b64 = manifest.get("artifact_sha256_base64")
    expected_bytes = manifest.get("artifact_bytes")
    expected_files = manifest.get("artifact_file_count")
    checks = [
        Check("artifact.source_state", manifest.get("source_state") == "clean", "must be clean"),
        Check(
            "artifact.architecture",
            manifest.get("architecture") == "linux-amd64",
            "must be linux-amd64",
        ),
        Check(
            "artifact.runtime",
            manifest.get("python_runtime") == "python3.12",
            "must be python3.12",
        ),
        Check(
            "artifact.sha256_hex",
            isinstance(expected_hex, str) and digest.hex() == expected_hex,
            "local bytes must match manifest",
        ),
        Check(
            "artifact.sha256_base64",
            isinstance(expected_b64, str)
            and base64.b64encode(digest).decode("ascii") == expected_b64,
            "local bytes must match manifest",
        ),
        Check(
            "artifact.size",
            isinstance(expected_bytes, int) and len(content) == expected_bytes,
            "local byte count must match manifest",
        ),
        Check(
            "artifact.file_count",
            isinstance(expected_files, int) and file_count == expected_files,
            "ZIP file count must match manifest",
        ),
        Check("artifact.safe_paths", not bad_paths, "ZIP paths must stay relative"),
    ]
    return checks, manifest


def verify_caller(identity: Mapping[str, Any], expected_account_id: str) -> list[Check]:
    arn = identity.get("Arn")
    account = identity.get("Account")
    match = _ADMIN_SESSION.fullmatch(arn) if isinstance(arn, str) else None
    return [
        Check(
            "aws.target_account",
            account == expected_account_id and match is not None
            and match.group("account") == expected_account_id,
            "caller and target account must match",
        ),
        Check(
            "aws.identity_center_admin",
            match is not None,
            "caller must be the LucySecurityAdministrator SSO session, not root",
        ),
    ]


def verify_lambda_quota(
    settings: Mapping[str, Any], required_unreserved_concurrency: int = 13
) -> list[Check]:
    limits = settings.get("AccountLimit")
    if not isinstance(limits, Mapping):
        return [Check("aws.lambda_quota", False, "Lambda account limits are missing")]
    total = limits.get("ConcurrentExecutions")
    unreserved = limits.get("UnreservedConcurrentExecutions")
    passed = (
        isinstance(total, int)
        and not isinstance(total, bool)
        and isinstance(unreserved, int)
        and not isinstance(unreserved, bool)
        and total >= required_unreserved_concurrency
        and unreserved >= required_unreserved_concurrency
    )
    return [
        Check(
            "aws.lambda_quota",
            passed,
            (
                f"requires at least {required_unreserved_concurrency} total and unreserved "
                "concurrency before stack creation"
            ),
        )
    ]


def verify_render_oidc(
    provider: Mapping[str, Any], *, workspace_id: str, provider_arn: str, account_id: str
) -> list[Check]:
    expected_arn = f"arn:aws:iam::{account_id}:oidc-provider/oidc.render.com/{workspace_id}"
    clients = provider.get("ClientIDList")
    thumbprints = provider.get("ThumbprintList")
    return [
        Check(
            "aws.render_oidc_arn",
            provider_arn == expected_arn,
            "provider ARN must bind the exact target account and Render workspace",
        ),
        Check(
            "aws.render_oidc_url",
            provider.get("Url") == f"oidc.render.com/{workspace_id}",
            "provider URL must bind the exact Render workspace",
        ),
        Check(
            "aws.render_oidc_audience",
            isinstance(clients, list) and set(clients) == {"sts.amazonaws.com"},
            "OIDC audience must be exactly sts.amazonaws.com",
        ),
        Check(
            "aws.render_oidc_thumbprint",
            isinstance(thumbprints, list)
            and bool(thumbprints)
            and all(
                isinstance(value, str) and re.fullmatch(r"[0-9A-Fa-f]{40}", value)
                for value in thumbprints
            ),
            "OIDC provider must expose valid TLS thumbprint metadata",
        ),
    ]


def verify_s3_artifact(
    response: Mapping[str, Any], *, expected_version: str, manifest: Mapping[str, Any]
) -> list[Check]:
    body = response.get("Body")
    if body is None:
        return [Check("aws.artifact_read", False, "S3 response omitted the artifact body")]
    digest = hashlib.sha256()
    observed_bytes = 0
    try:
        while True:
            chunk = body.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            observed_bytes += len(chunk)
    except (AttributeError, OSError) as exc:
        return [Check("aws.artifact_read", False, f"S3 artifact unreadable: {type(exc).__name__}")]
    finally:
        close = getattr(body, "close", None)
        if callable(close):
            close()

    encryption = response.get("ServerSideEncryption")
    return [
        Check(
            "aws.artifact_version",
            bool(expected_version) and response.get("VersionId") == expected_version,
            "S3 returned the exact requested immutable object version",
        ),
        Check(
            "aws.artifact_sha256",
            digest.hexdigest() == manifest.get("artifact_sha256_hex"),
            "full S3 object bytes must match the clean local release manifest",
        ),
        Check(
            "aws.artifact_size",
            observed_bytes == manifest.get("artifact_bytes")
            and response.get("ContentLength") == manifest.get("artifact_bytes"),
            "streamed and reported S3 byte counts must match the manifest",
        ),
        Check(
            "aws.artifact_encryption",
            encryption in {"AES256", "aws:kms", "aws:kms:dsse"},
            "S3 artifact must be encrypted at rest",
        ),
    ]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--expected-account-id", required=True)
    parser.add_argument("--render-workspace-id", required=True)
    parser.add_argument("--oidc-provider-arn", required=True)
    parser.add_argument("--artifact-bucket", required=True)
    parser.add_argument("--artifact-key", required=True)
    parser.add_argument("--artifact-version", required=True)
    parser.add_argument("--region", choices=("us-east-1",), default="us-east-1")
    parser.add_argument("--required-unreserved-concurrency", type=int, default=13)
    parser.add_argument("--report", type=Path)
    return parser


def _validate_arguments(args: argparse.Namespace) -> None:
    if _ACCOUNT_ID.fullmatch(args.expected_account_id) is None:
        raise ValueError("expected AWS account ID must contain exactly 12 digits")
    if _WORKSPACE_ID.fullmatch(args.render_workspace_id) is None:
        raise ValueError("invalid Render workspace ID")
    if args.required_unreserved_concurrency < 13:
        raise ValueError("v1.2 preflight cannot require less than 13 unreserved concurrency")
    if not args.artifact_bucket or not args.artifact_key or not args.artifact_version:
        raise ValueError("an exact versioned S3 artifact is required")
    if args.report is not None:
        if args.report.exists():
            raise FileExistsError(f"refusing to overwrite report: {args.report}")
        if not args.report.parent.is_dir():
            raise FileNotFoundError(f"report directory does not exist: {args.report.parent}")


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    checks: list[Check] = []
    try:
        _validate_arguments(args)
        local_checks, manifest = verify_local_artifact(args.artifact, args.manifest)
        checks.extend(local_checks)
        session = boto3.Session(region_name=args.region)
        identity = session.client("sts").get_caller_identity()
        checks.extend(verify_caller(identity, args.expected_account_id))
        settings = session.client("lambda").get_account_settings()
        checks.extend(verify_lambda_quota(settings, args.required_unreserved_concurrency))
        provider = session.client("iam").get_open_id_connect_provider(
            OpenIDConnectProviderArn=args.oidc_provider_arn
        )
        checks.extend(
            verify_render_oidc(
                provider,
                workspace_id=args.render_workspace_id,
                provider_arn=args.oidc_provider_arn,
                account_id=args.expected_account_id,
            )
        )
        s3_response = session.client("s3").get_object(
            Bucket=args.artifact_bucket,
            Key=args.artifact_key,
            VersionId=args.artifact_version,
        )
        checks.extend(
            verify_s3_artifact(
                s3_response,
                expected_version=args.artifact_version,
                manifest=manifest,
            )
        )
    except Exception as exc:  # CLI boundary: emit type only, never provider payloads.
        checks.append(Check("preflight.execution", False, f"failed: {type(exc).__name__}"))

    def render_report() -> tuple[dict[str, Any], str]:
        report = {
            "object_type": "lucy.security-baseline-v1.2-preflight",
            "region": args.region,
            "passed": all(check.passed for check in checks),
            "checks": [asdict(check) for check in checks],
        }
        return report, json.dumps(report, indent=2, sort_keys=True) + "\n"

    report, rendered = render_report()
    if args.report is not None:
        try:
            with args.report.open("x", encoding="utf-8", newline="\n") as handle:
                handle.write(rendered)
        except OSError as exc:
            checks.append(
                Check("preflight.report", False, f"report not written: {type(exc).__name__}")
            )
            report, rendered = render_report()
    sys.stdout.write(rendered)
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
