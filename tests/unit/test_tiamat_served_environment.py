"""The deployed serving process is built from its environment, or refuses to start."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lucy.shared_execution.served_environment import (
    ServedEnvironmentRejected,
    SyntheticTransport,
    served_configuration_from_environment,
)

ROOT = Path(__file__).resolve().parents[2]
TRUST = ROOT / "deploy/aws/tiamat-staging-quarantine-successor-v3-public-2026-09-22.json"
NOW = datetime(2026, 9, 22, 15, tzinfo=UTC)


def _raw(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _environment() -> dict[str, str]:
    package = json.loads(TRUST.read_text(encoding="utf-8"))
    release_root = _raw(Ed25519PrivateKey.generate())
    return {
        "TIAMAT_PROVIDER_TRANSPORT": "synthetic",
        "TIAMAT_ANCHOR_TRUST_PATH": str(TRUST),
        "TIAMAT_EXPECTED_LEDGER_ID": str(package["ledger_id"]),
        "TIAMAT_RECOVERY_ANCHOR_TABLE": "stoin-staging-tiamat-recovery-anchor-v1",
        "AWS_REGION": "us-east-1",
        "TIAMAT_RUNTIME_DATABASE_URL": "postgresql://runtime@example.invalid/tiamat",
        "TIAMAT_RECOVERY_GENERATION": "1",
        "TIAMAT_LEDGER_ISSUER": "stoin:control",
        "TIAMAT_CALLER_ID": "stoin:synth:utopia-homes-prime",
        "TIAMAT_REALM": "utopia-homes",
        "TIAMAT_PARTITION_ID": "utopia-public",
        "TIAMAT_WORKLOAD_ISSUER": "https://homes.internal",
        "TIAMAT_WORKLOAD_SUBJECT": "stoin:synth:utopia-homes-prime",
        "TIAMAT_WORKLOAD_REALM": "utopia-homes",
        "TIAMAT_WORKLOAD_KEYS_JSON": json.dumps(
            {"homes-prime-staging-1": base64.b64encode(_raw(Ed25519PrivateKey.generate())).decode()}
        ),
        "TIAMAT_EXECUTION_PROFILES": "utopia-homes.public-answer.generate.v1",
        "TIAMAT_AUTHORITY_ISSUER": "stoin-control",
        "TIAMAT_RELEASE_ROOT_KEY_ID": "tiamat-trust-root-staging-1",
        "TIAMAT_RELEASE_ROOT_PUBLIC_KEY_B64": base64.b64encode(release_root).decode(),
        "TIAMAT_RELEASE_ROOT_PUBLIC_KEY_SHA256": hashlib.sha256(release_root).hexdigest(),
        "TIAMAT_IDEMPOTENCY_DIGEST_KEY_VERSION": "digest-staging-1",
        "TIAMAT_IDEMPOTENCY_DIGEST_KEY_B64": base64.b64encode(b"k" * 32).decode(),
        "TIAMAT_EXECUTION_RELEASE": "tiamat-staging.1",
        "TIAMAT_POLICY_RELEASE": "profiles-staging.1",
    }


def test_a_complete_environment_builds_a_consume_only_synthetic_process() -> None:
    configuration = served_configuration_from_environment(_environment(), now=NOW)

    assert configuration.recovery_database_url is None
    assert isinstance(configuration.transport, SyntheticTransport)
    package = json.loads(TRUST.read_text(encoding="utf-8"))
    assert configuration.scope.environment == package["environment"]
    assert str(configuration.anchor_identity.ledger_id) == package["ledger_id"]


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        (
            {"TIAMAT_RECOVERY_DATABASE_URL": "postgresql://recovery@example.invalid/x"},
            "must not hold the recovery credential",
        ),
        ({"TIAMAT_PROVIDER_TRANSPORT": "openrouter"}, "only the synthetic transport"),
        ({"TIAMAT_EXPECTED_LEDGER_ID": "00000000-0000-4000-8000-000000000000"}, "different ledger"),
        ({"TIAMAT_RELEASE_ROOT_PUBLIC_KEY_SHA256": "0" * 64}, "does not match its pin"),
        ({"TIAMAT_RUNTIME_DATABASE_URL": ""}, "TIAMAT_RUNTIME_DATABASE_URL is required"),
        ({"TIAMAT_WORKLOAD_KEYS_JSON": "{}"}, "names no key"),
    ],
)
def test_an_environment_that_may_not_serve_is_refused(change: dict[str, str], reason: str) -> None:
    with pytest.raises(ServedEnvironmentRejected, match=reason):
        served_configuration_from_environment({**_environment(), **change}, now=NOW)
