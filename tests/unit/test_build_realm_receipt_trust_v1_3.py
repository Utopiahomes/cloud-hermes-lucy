from __future__ import annotations

import importlib.util
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from lucy.contracts.security_v1_2 import SignatureAlgorithm
from lucy.contracts.security_v1_3 import V13ContractVerifier, V13SigningKeyPurpose

ROOT = Path(__file__).parents[2]


def _module() -> ModuleType:
    path = ROOT / "deploy" / "aws" / "build_realm_receipt_trust_v1_3.py"
    spec = importlib.util.spec_from_file_location("build_realm_receipt_trust_v1_3", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _public_key() -> bytes:
    return ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def test_builds_two_purpose_separated_public_receipt_keys() -> None:
    outputs = {
        "RetrievalExecutorIdentity": "lucy-utopia-evidence-executor",
        "RetrievalReceiptKeyArn": "arn:aws:kms:us-east-1:123456789012:key/retrieval",
        "DeletionExecutorIdentity": "lucy-utopia-deletion-executor",
        "DeletionReceiptKeyArn": "arn:aws:kms:us-east-1:123456789012:key/deletion",
        "SecurityEnvironment": "production",
    }
    responses = {
        key_arn: {
            "KeyId": key_arn,
            "KeySpec": "ECC_NIST_P256",
            "KeyUsage": "SIGN_VERIFY",
            "SigningAlgorithms": ["ECDSA_SHA_256"],
            "PublicKey": _public_key(),
        }
        for key_arn in (
            outputs["RetrievalReceiptKeyArn"],
            outputs["DeletionReceiptKeyArn"],
        )
    }
    trust = _module().build_receipt_trust(
        outputs=outputs,
        public_keys=responses,
        valid_from=datetime(2026, 9, 9, tzinfo=UTC),
    )
    assert [key.purpose for key in trust] == [
        V13SigningKeyPurpose.RETRIEVAL_RECEIPT,
        V13SigningKeyPurpose.DELETION_RECEIPT,
    ]
    assert all(key.algorithm == SignatureAlgorithm.ECDSA_SHA_256 for key in trust)
    V13ContractVerifier(trust)


def test_rejects_a_key_without_exact_signing_metadata() -> None:
    outputs = {
        "RetrievalExecutorIdentity": "lucy-utopia-evidence-executor",
        "RetrievalReceiptKeyArn": "arn:aws:kms:us-east-1:123456789012:key/retrieval",
        "DeletionExecutorIdentity": "lucy-utopia-deletion-executor",
        "DeletionReceiptKeyArn": "arn:aws:kms:us-east-1:123456789012:key/deletion",
        "SecurityEnvironment": "production",
    }
    responses = {
        key_arn: {
            "KeyId": key_arn,
            "KeySpec": "RSA_2048",
            "KeyUsage": "SIGN_VERIFY",
            "SigningAlgorithms": ["RSASSA_PSS_SHA_256"],
            "PublicKey": b"not-a-key",
        }
        for key_arn in (
            outputs["RetrievalReceiptKeyArn"],
            outputs["DeletionReceiptKeyArn"],
        )
    }
    with pytest.raises(ValueError, match="does not match"):
        _module().build_receipt_trust(
            outputs=outputs,
            public_keys=responses,
            valid_from=datetime(2026, 9, 9, tzinfo=UTC),
        )


def test_accepts_only_successful_create_or_update_stack_states() -> None:
    module = _module()
    assert {"CREATE_COMPLETE", "UPDATE_COMPLETE"} == module.COMPLETE_STACK_STATUSES
    assert "UPDATE_ROLLBACK_COMPLETE" not in module.COMPLETE_STACK_STATUSES
