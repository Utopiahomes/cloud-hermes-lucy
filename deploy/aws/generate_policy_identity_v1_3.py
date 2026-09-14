"""Generate one V1.3 policy-notary identity into ignored local files."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519

from lucy.contracts.security_v1_2 import DeploymentEnvironment
from lucy.contracts.security_v1_3 import (
    V13SigningKeyPurpose,
    V13VerificationKeyStatus,
    V13VerificationKeyV1,
)


def generate_identity(
    *,
    key_id: str,
    issuer: str,
    environment: DeploymentEnvironment,
    now: datetime,
) -> tuple[dict[str, str], tuple[V13VerificationKeyV1, ...]]:
    private = ed25519.Ed25519PrivateKey.generate()
    seed = private.private_bytes_raw()
    public = private.public_key().public_bytes_raw()
    verification = V13VerificationKeyV1(
        key_id=key_id,
        issuer=issuer,
        environment=environment,
        purpose=V13SigningKeyPurpose.POLICY_NOTARY,
        public_key_b64=base64.b64encode(public).decode("ascii"),
        status=V13VerificationKeyStatus.ACTIVE,
        valid_from=now,
        issuance_not_after=now + timedelta(days=365),
        verify_not_after=now + timedelta(days=366),
    )
    secret = {
        "contract": "lucy.v13-policy-private-key.local.v1",
        "key_id": key_id,
        "private_key_b64": base64.b64encode(seed).decode("ascii"),
    }
    return secret, (verification,)


def _write_new(path: Path, payload: object) -> None:
    path = path.resolve()
    if path.exists():
        raise FileExistsError(f"refusing to overwrite existing identity file: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    try:
        os.chmod(path, 0o600)
    except OSError:
        path.unlink(missing_ok=True)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--issuer", required=True)
    parser.add_argument("--environment", choices=("production", "development"), required=True)
    parser.add_argument("--private-output", type=Path, required=True)
    parser.add_argument("--trust-output", type=Path, required=True)
    arguments = parser.parse_args()
    if arguments.private_output.resolve() == arguments.trust_output.resolve():
        raise ValueError("private and public identity outputs must be distinct")
    secret, trust = generate_identity(
        key_id=arguments.key_id,
        issuer=arguments.issuer,
        environment=DeploymentEnvironment(arguments.environment),
        now=datetime.now(UTC).replace(microsecond=0),
    )
    _write_new(arguments.private_output, secret)
    try:
        public_payload = [key.model_dump(mode="json") for key in trust]
        _write_new(arguments.trust_output, public_payload)
    except Exception:
        arguments.private_output.resolve().unlink(missing_ok=True)
        raise
    canonical_public = json.dumps(public_payload, separators=(",", ":"), sort_keys=True)
    print(
        json.dumps(
            {
                "status": "created",
                "key_id": arguments.key_id,
                "public_trust_sha256": hashlib.sha256(
                    canonical_public.encode("utf-8")
                ).hexdigest(),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
