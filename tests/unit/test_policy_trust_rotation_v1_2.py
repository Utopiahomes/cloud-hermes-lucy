from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from deploy.aws.rotate_policy_trust_v1_2 import canonical_trust_store, update_parameters


def _key() -> dict[str, str]:
    return {
        "algorithm": "Ed25519",
        "contract_version": "1",
        "environment": "production",
        "issuance_not_after": "2027-09-04T00:00:00Z",
        "issuer": "lucy-policy",
        "key_id": "policy-notary.production.2",
        "object_type": "lucy.verification-key.v1",
        "public_key_b64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "purpose": "policy_notary",
        "status": "active",
        "valid_from": "2026-09-04T00:00:00Z",
        "verify_not_after": "2027-09-05T00:00:00Z",
    }


def test_canonical_trust_store_accepts_only_the_expected_active_key(tmp_path: Path) -> None:
    path = tmp_path / "trust.json"
    path.write_text(json.dumps([_key()], indent=2), encoding="utf-8")

    canonical, digest = canonical_trust_store(path, "policy-notary.production.2")

    assert canonical == json.dumps([_key()], sort_keys=True, separators=(",", ":"))
    assert digest == hashlib.sha256(canonical.encode()).hexdigest()


def test_canonical_trust_store_rejects_old_or_additional_keys(tmp_path: Path) -> None:
    path = tmp_path / "trust.json"
    path.write_text(json.dumps([_key(), _key()]), encoding="utf-8")

    with pytest.raises(ValueError, match="exactly one"):
        canonical_trust_store(path, "policy-notary.production.2")


def test_update_parameters_replaces_only_trust_inputs() -> None:
    observed = update_parameters(
        [
            {"ParameterKey": "ResourceNamespace", "ParameterValue": "lucy-prod-v12"},
            {"ParameterKey": "PolicyTrustStoreJson", "ParameterValue": "masked"},
            {"ParameterKey": "PolicyTrustStoreSha256", "ParameterValue": "0" * 64},
        ],
        trust_store="[]",
        digest="f" * 64,
    )

    assert observed == [
        {"ParameterKey": "PolicyTrustStoreJson", "ParameterValue": "[]"},
        {"ParameterKey": "PolicyTrustStoreSha256", "ParameterValue": "f" * 64},
        {"ParameterKey": "ResourceNamespace", "UsePreviousValue": True},
    ]
