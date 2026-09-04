"""Rotate the production policy-notary trust boundary in one AWS session.

The private Ed25519 seed belongs only to the Render policy service and is never
accepted by this command. This utility receives a public verification-key
inventory, updates the existing CloudFormation stack, verifies the newly
published executor versions, and preserves the previous versions for rollback.
Temporary Identity Center credentials remain process-local.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import time
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import boto3  # type: ignore[import-untyped]
from botocore import UNSIGNED  # type: ignore[import-untyped]
from botocore.config import Config  # type: ignore[import-untyped]
from botocore.exceptions import ClientError  # type: ignore[import-untyped]

try:
    from .verify_security_v1_2_deployment import verify_policy_trust_store
except ImportError:  # Direct script execution places deploy/aws on sys.path.
    from verify_security_v1_2_deployment import verify_policy_trust_store

_ADMIN_SESSION = re.compile(
    r"arn:aws:sts::(?P<account>[0-9]{12}):assumed-role/"
    r"AWSReservedSSO_LucySecurityAdministrator_[A-Za-z0-9]+/[^/]+\Z"
)
_ACCOUNT_ID = re.compile(r"[0-9]{12}\Z")
_STACK_NAME = re.compile(r"[A-Za-z][A-Za-z0-9-]{0,127}\Z")
_KEY_ID = re.compile(r"policy-notary\.production\.[1-9][0-9]*\Z")
_TERMINAL_FAILURE = {
    "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_ROLLBACK_FAILED",
}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--start-url", required=True)
    parser.add_argument("--sso-region", choices=("us-east-1",), default="us-east-1")
    parser.add_argument("--account-id", required=True)
    parser.add_argument("--role-name", required=True)
    parser.add_argument("--stack-name", required=True)
    parser.add_argument("--trust-store", required=True, type=Path)
    parser.add_argument("--expected-key-id", required=True)
    parser.add_argument("--report-dir", required=True, type=Path)
    parser.add_argument("--wait-seconds", type=int, default=1800)
    return parser


def canonical_trust_store(path: Path, expected_key_id: str) -> tuple[str, str]:
    """Return the exact compact public inventory and its SHA-256 digest."""

    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list) or len(raw) != 1:
        raise ValueError("rotation trust store must contain exactly one public key")
    key = raw[0]
    if not isinstance(key, Mapping):
        raise ValueError("rotation trust store contains an invalid key")
    if (
        key.get("key_id") != expected_key_id
        or _KEY_ID.fullmatch(expected_key_id) is None
        or key.get("issuer") != "lucy-policy"
        or key.get("status") != "active"
    ):
        raise ValueError("rotation trust store does not contain the expected active key")
    canonical = json.dumps(raw, sort_keys=True, separators=(",", ":"))
    if not verify_policy_trust_store(canonical):
        raise ValueError("rotation trust store does not satisfy the deployed verifier")
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return canonical, digest


def update_parameters(
    existing: Sequence[Mapping[str, Any]], *, trust_store: str, digest: str
) -> list[dict[str, Any]]:
    """Preserve every stack parameter except the two reviewed rotation inputs."""

    names = {
        str(item.get("ParameterKey"))
        for item in existing
        if isinstance(item.get("ParameterKey"), str)
    }
    required = {"PolicyTrustStoreJson", "PolicyTrustStoreSha256"}
    if not required <= names:
        raise RuntimeError("stack is missing policy trust-store parameters")
    result: list[dict[str, Any]] = []
    for name in sorted(names):
        if name == "PolicyTrustStoreJson":
            result.append({"ParameterKey": name, "ParameterValue": trust_store})
        elif name == "PolicyTrustStoreSha256":
            result.append({"ParameterKey": name, "ParameterValue": digest})
        else:
            result.append({"ParameterKey": name, "UsePreviousValue": True})
    return result


def _authorize(args: argparse.Namespace) -> dict[str, str]:
    unsigned = Config(signature_version=UNSIGNED)
    oidc = boto3.client("sso-oidc", region_name=args.sso_region, config=unsigned)
    registration = oidc.register_client(
        clientName="cloud-hermes-lucy-policy-trust-rotation",
        clientType="public",
        scopes=["sso:account:access"],
    )
    authorization = oidc.start_device_authorization(
        clientId=registration["clientId"],
        clientSecret=registration["clientSecret"],
        startUrl=args.start_url,
    )
    print("Open this AWS verification URL and approve the planned rotation session:")
    print(authorization["verificationUriComplete"])
    print("Waiting for authorization; no credential material will be displayed.", flush=True)

    interval = max(int(authorization.get("interval", 5)), 1)
    deadline = time.monotonic() + int(authorization["expiresIn"])
    while time.monotonic() < deadline:
        try:
            token = oidc.create_token(
                clientId=registration["clientId"],
                clientSecret=registration["clientSecret"],
                deviceCode=authorization["deviceCode"],
                grantType="urn:ietf:params:oauth:grant-type:device_code",
            )
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "AuthorizationPendingException":
                time.sleep(interval)
                continue
            if code == "SlowDownException":
                interval += 5
                time.sleep(interval)
                continue
            raise
    else:
        raise TimeoutError("AWS device authorization expired")

    sso = boto3.client("sso", region_name=args.sso_region, config=unsigned)
    credentials = sso.get_role_credentials(
        roleName=args.role_name,
        accountId=args.account_id,
        accessToken=token["accessToken"],
    )["roleCredentials"]
    return {
        "AWS_ACCESS_KEY_ID": credentials["accessKeyId"],
        "AWS_SECRET_ACCESS_KEY": credentials["secretAccessKey"],
        "AWS_SESSION_TOKEN": credentials["sessionToken"],
        "AWS_DEFAULT_REGION": args.sso_region,
        "AWS_REGION": args.sso_region,
    }


def _outputs(stack: Mapping[str, Any]) -> dict[str, str]:
    return {
        str(item["OutputKey"]): str(item["OutputValue"])
        for item in stack.get("Outputs", [])
        if isinstance(item, Mapping) and "OutputKey" in item and "OutputValue" in item
    }


def _wait_for_update(cloudformation: Any, stack_name: str, seconds: int) -> dict[str, Any]:
    deadline = time.monotonic() + seconds
    previous: str | None = None
    while time.monotonic() < deadline:
        stack = cloudformation.describe_stacks(StackName=stack_name)["Stacks"][0]
        status = str(stack.get("StackStatus"))
        if status != previous:
            print(f"CloudFormation progress: {status}", flush=True)
            previous = status
        if status == "UPDATE_COMPLETE":
            return stack
        if status in _TERMINAL_FAILURE or status.startswith("DELETE"):
            raise RuntimeError(f"policy trust rotation failed with stack state {status}")
        time.sleep(5)
    raise TimeoutError("policy trust rotation did not reach UPDATE_COMPLETE")


def _run_verifiers(args: argparse.Namespace) -> dict[str, Any]:
    try:
        from .verify_security_v1_2_audit import main as audit_main
        from .verify_security_v1_2_deployment import main as deployment_main
        from .verify_security_v1_2_iam import main as iam_main
    except ImportError:  # Direct script execution places deploy/aws on sys.path.
        from verify_security_v1_2_audit import main as audit_main
        from verify_security_v1_2_deployment import main as deployment_main
        from verify_security_v1_2_iam import main as iam_main

    common = [
        "--stack-name",
        args.stack_name,
        "--expected-account-id",
        args.account_id,
        "--region",
        args.sso_region,
    ]
    checks: tuple[tuple[str, Callable[[Sequence[str] | None], int], list[str]], ...] = (
        ("deployment", deployment_main, common),
        ("iam", iam_main, common),
        (
            "audit",
            audit_main,
            common + ["--expected-alert-email", "ray@utopiahomes.com"],
        ),
    )
    results: dict[str, Any] = {}
    for name, verifier, arguments in checks:
        path = args.report_dir / f"aws-policy-rotation-{name}-v1.2.json"
        if path.exists():
            raise FileExistsError(f"refusing to overwrite rotation verifier report: {path.name}")
        exit_code = verifier(arguments + ["--report", str(path)])
        report = json.loads(path.read_text(encoding="utf-8"))
        results[name] = {
            "passed": exit_code == 0 and report.get("passed") is True,
            "report": path.name,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
    if not all(item["passed"] for item in results.values()):
        raise RuntimeError("one or more post-rotation verifiers failed")
    return results


def _verify_versions(
    lambdas: Any,
    *,
    previous: Mapping[str, str],
    current: Mapping[str, str],
    trust_store: str,
) -> dict[str, Any]:
    observed: dict[str, Any] = {}
    for title, function_name in (
        ("Retrieval", "lucy-evidence-executor-v12"),
        ("Deletion", "lucy-deletion-executor-v12"),
    ):
        output_name = f"{title}ExecutorVersion"
        prior_version = previous.get(output_name)
        version = current.get(output_name)
        if not prior_version or not version or prior_version == version:
            raise RuntimeError(f"{title.lower()} executor did not publish a new version")
        old = lambdas.get_function_configuration(
            FunctionName=function_name,
            Qualifier=prior_version,
        )
        new = lambdas.get_function_configuration(FunctionName=function_name, Qualifier=version)
        alias = lambdas.get_alias(FunctionName=function_name, Name="production")
        variables = new.get("Environment", {}).get("Variables", {})
        if (
            old.get("Version") != prior_version
            or new.get("Version") != version
            or alias.get("FunctionVersion") != version
            or variables.get("LUCY_POLICY_TRUST_STORE_JSON") != trust_store
            or old.get("CodeSha256") != new.get("CodeSha256")
        ):
            raise RuntimeError(f"{title.lower()} executor version transition is invalid")
        observed[title.lower()] = {
            "previous_version_retained": prior_version,
            "production_version": version,
            "artifact_digest_unchanged": True,
        }
    return observed


def _validate_args(args: argparse.Namespace) -> None:
    if _ACCOUNT_ID.fullmatch(args.account_id) is None:
        raise ValueError("account ID must contain exactly 12 digits")
    if _STACK_NAME.fullmatch(args.stack_name) is None:
        raise ValueError("invalid CloudFormation stack name")
    if args.role_name != "LucySecurityAdministrator":
        raise ValueError("rotation requires the exact Security Administrator permission set")
    if args.wait_seconds < 1:
        raise ValueError("wait duration must be positive")
    if not args.report_dir.is_dir():
        raise FileNotFoundError("report directory does not exist")


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    _validate_args(args)
    trust_store, digest = canonical_trust_store(args.trust_store, args.expected_key_id)
    final_report = args.report_dir / "aws-policy-rotation-v1.2.json"
    if final_report.exists():
        raise FileExistsError("refusing to overwrite the policy rotation report")

    temporary = _authorize(args)
    previous_environment = {name: os.environ.get(name) for name in temporary}
    os.environ.update(temporary)
    try:
        session = boto3.Session(region_name=args.sso_region)
        identity = session.client("sts").get_caller_identity()
        arn = identity.get("Arn")
        match = _ADMIN_SESSION.fullmatch(arn) if isinstance(arn, str) else None
        if identity.get("Account") != args.account_id or match is None:
            raise PermissionError("caller is not the exact target-account security administrator")

        cloudformation = session.client("cloudformation")
        before = cloudformation.describe_stacks(StackName=args.stack_name)["Stacks"][0]
        if before.get("StackStatus") != "UPDATE_COMPLETE":
            raise RuntimeError("stack must be stable before policy trust rotation")
        if before.get("EnableTerminationProtection") is not True:
            raise RuntimeError("stack termination protection is not enabled")
        previous_outputs = _outputs(before)
        if previous_outputs.get("PolicyTrustStoreSha256") == digest:
            raise RuntimeError("stack already contains this trust-store digest")

        token = f"lucy-policy-trust-{digest[:32]}"
        cloudformation.update_stack(
            StackName=args.stack_name,
            UsePreviousTemplate=True,
            Parameters=update_parameters(
                before.get("Parameters", []),
                trust_store=trust_store,
                digest=digest,
            ),
            Capabilities=["CAPABILITY_NAMED_IAM"],
            ClientRequestToken=token,
        )
        after = _wait_for_update(cloudformation, args.stack_name, args.wait_seconds)
        if after.get("EnableTerminationProtection") is not True:
            raise RuntimeError("termination protection changed during rotation")
        current_outputs = _outputs(after)
        if current_outputs.get("PolicyTrustStoreSha256") != digest:
            raise RuntimeError("stack output does not contain the reviewed trust-store digest")
        versions = _verify_versions(
            session.client("lambda"),
            previous=previous_outputs,
            current=current_outputs,
            trust_store=trust_store,
        )
        verifiers = _run_verifiers(args)
        report = {
            "object_type": "lucy.security-baseline-v1.2-policy-trust-rotation",
            "recorded_at": datetime.now(UTC).isoformat(),
            "account_id": args.account_id,
            "region": args.sso_region,
            "stack_name": args.stack_name,
            "key_id": args.expected_key_id,
            "policy_trust_store_sha256": digest,
            "termination_protection": True,
            "executors": versions,
            "verifiers": verifiers,
            "passed": True,
            "transcript_capture_enabled": False,
        }
        with final_report.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    finally:
        for name, value in previous_environment.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


if __name__ == "__main__":
    raise SystemExit(main())
