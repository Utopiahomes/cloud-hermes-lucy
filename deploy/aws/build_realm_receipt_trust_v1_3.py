"""Build a public V1.3 executor-receipt trust inventory from one deployed realm stack."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import boto3  # type: ignore[import-untyped]

from lucy.contracts.security_v1_2 import DeploymentEnvironment, SignatureAlgorithm
from lucy.contracts.security_v1_3 import (
    V13SigningKeyPurpose,
    V13VerificationKeyStatus,
    V13VerificationKeyV1,
)

_REQUIRED_OUTPUTS = {
    "RetrievalExecutorIdentity",
    "RetrievalReceiptKeyArn",
    "DeletionExecutorIdentity",
    "DeletionReceiptKeyArn",
    "SecurityEnvironment",
}


def build_receipt_trust(
    *,
    outputs: Mapping[str, str],
    public_keys: Mapping[str, Mapping[str, Any]],
    valid_from: datetime,
) -> tuple[V13VerificationKeyV1, ...]:
    """Validate AWS key metadata and construct two purpose-separated public keys."""

    missing = _REQUIRED_OUTPUTS - set(outputs)
    if missing:
        raise ValueError("realm stack receipt outputs are incomplete")
    if outputs["SecurityEnvironment"] != "production" or valid_from.tzinfo is None:
        raise ValueError("receipt trust requires an aware production deployment time")
    entries: list[V13VerificationKeyV1] = []
    for prefix, purpose in (
        ("Retrieval", V13SigningKeyPurpose.RETRIEVAL_RECEIPT),
        ("Deletion", V13SigningKeyPurpose.DELETION_RECEIPT),
    ):
        key_arn = outputs[f"{prefix}ReceiptKeyArn"]
        response = public_keys.get(key_arn)
        if response is None:
            raise ValueError("receipt public-key response is missing")
        algorithms = response.get("SigningAlgorithms")
        material = response.get("PublicKey")
        if (
            response.get("KeyId") != key_arn
            or response.get("KeySpec") != "ECC_NIST_P256"
            or response.get("KeyUsage") != "SIGN_VERIFY"
            or not isinstance(algorithms, list)
            or "ECDSA_SHA_256" not in algorithms
            or not isinstance(material, bytes)
        ):
            raise ValueError("receipt signing key does not match the V1.3 boundary")
        entries.append(
            V13VerificationKeyV1(
                key_id=key_arn,
                issuer=outputs[f"{prefix}ExecutorIdentity"],
                environment=DeploymentEnvironment.PRODUCTION,
                purpose=purpose,
                algorithm=SignatureAlgorithm.ECDSA_SHA_256,
                public_key_b64=base64.b64encode(material).decode("ascii"),
                status=V13VerificationKeyStatus.ACTIVE,
                valid_from=valid_from.astimezone(UTC),
                issuance_not_after=valid_from.astimezone(UTC) + timedelta(days=365),
                verify_not_after=valid_from.astimezone(UTC) + timedelta(days=366),
            )
        )
    return tuple(entries)


def _outputs(stack: Mapping[str, Any]) -> dict[str, str]:
    values: dict[str, str] = {}
    for item in stack.get("Outputs", []):
        if isinstance(item, dict):
            key, value = item.get("OutputKey"), item.get("OutputValue")
            if isinstance(key, str) and isinstance(value, str):
                values[key] = value
    return values


def _write_new(path: Path, payload: object, *, overwrite: bool) -> None:
    resolved = path.resolve()
    if resolved.exists() and not overwrite:
        raise FileExistsError(f"refusing to overwrite existing trust inventory: {resolved}")
    if not resolved.parent.is_dir():
        raise FileNotFoundError(f"output directory does not exist: {resolved.parent}")
    resolved.write_text(
        json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stack-name", required=True)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--profile", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--overwrite", action="store_true")
    arguments = parser.parse_args(argv)
    session = boto3.Session(profile_name=arguments.profile, region_name=arguments.region)
    cloudformation = session.client("cloudformation")
    stacks = cloudformation.describe_stacks(StackName=arguments.stack_name).get("Stacks", [])
    if len(stacks) != 1 or stacks[0].get("StackStatus") != "CREATE_COMPLETE":
        raise RuntimeError("realm stack is not in its reviewed complete state")
    stack = stacks[0]
    outputs = _outputs(stack)
    created_at = stack.get("CreationTime")
    if not isinstance(created_at, datetime):
        raise RuntimeError("realm stack creation time is unavailable")
    kms = session.client("kms")
    key_arns = {
        outputs.get("RetrievalReceiptKeyArn", ""),
        outputs.get("DeletionReceiptKeyArn", ""),
    }
    if "" in key_arns:
        raise RuntimeError("realm stack receipt-key outputs are unavailable")
    responses = {key_arn: kms.get_public_key(KeyId=key_arn) for key_arn in key_arns}
    trust = build_receipt_trust(
        outputs=outputs,
        public_keys=responses,
        valid_from=created_at,
    )
    payload = [entry.model_dump(mode="json") for entry in trust]
    _write_new(arguments.output, payload, overwrite=arguments.overwrite)
    canonical = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    print(
        json.dumps(
            {
                "status": "created",
                "key_count": len(payload),
                "public_trust_sha256": hashlib.sha256(canonical.encode()).hexdigest(),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
