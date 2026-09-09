from __future__ import annotations

import json
from typing import Any
from uuid import UUID

import pytest
from botocore.exceptions import ClientError

from lucy.contracts.security_v1_3 import KmsEncryptionContextV2
from lucy.realm_archive_aws import AwsRealmArchiveBackend

ACCOUNT = "123456789012"
KEY_ARN = (
    f"arn:aws:kms:us-east-1:{ACCOUNT}:key/11111111-1111-4111-8111-111111111111"
)


def _context() -> KmsEncryptionContextV2:
    return KmsEncryptionContextV2(
        tenant_account_id=UUID(int=1),
        node_id=UUID(int=2),
        node_tenure_id=UUID(int=3),
        tenure_epoch=1,
        security_realm_id=UUID(int=4),
        storage_epoch=2,
        evidence_id=UUID(int=5),
    )


class FakeKms:
    def __init__(self, response: dict[str, Any] | None = None) -> None:
        self.calls: list[dict[str, Any]] = []
        self.response = response or {
            "Plaintext": b"d" * 32,
            "CiphertextBlob": b"wrapped",
            "KeyId": KEY_ARN,
            "ResponseMetadata": {"RequestId": "request-1"},
        }

    def generate_data_key(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        return self.response


class FakeDynamo:
    def __init__(self, error: ClientError | None = None) -> None:
        self.calls: list[dict[str, Any]] = []
        self.error = error

    def put_item(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return {}


def _backend(
    kms: FakeKms | None = None, dynamo: FakeDynamo | None = None
) -> AwsRealmArchiveBackend:
    return AwsRealmArchiveBackend(
        kms or FakeKms(),
        dynamo or FakeDynamo(),
        evidence_key_arn=KEY_ARN,
        wrapped_key_table="lucy-utopia-wrapped-keys",
    )


def test_backend_generates_only_on_the_configured_key() -> None:
    kms = FakeKms()
    result = _backend(kms=kms).generate_data_key(
        key_arn=KEY_ARN, encryption_context=_context().as_aws_context()
    )
    assert result.plaintext == b"d" * 32
    assert result.ciphertext == b"wrapped"
    assert result.request_id == "request-1"
    assert kms.calls == [
        {
            "KeyId": KEY_ARN,
            "KeySpec": "AES_256",
            "EncryptionContext": _context().as_aws_context(),
        }
    ]
    with pytest.raises(PermissionError, match="unconfigured"):
        _backend().generate_data_key(
            key_arn=KEY_ARN.replace("11111111", "99999999"),
            encryption_context=_context().as_aws_context(),
        )


def test_backend_stores_exact_realm_metadata_without_read_or_delete() -> None:
    dynamo = FakeDynamo()
    backend = _backend(dynamo=dynamo)
    backend.put_wrapped_key(
        key_ref=UUID(int=6),
        wrapped_key=b"wrapped",
        key_arn=KEY_ARN,
        encryption_context=_context(),
    )
    assert not hasattr(backend, "get_wrapped_key")
    assert not hasattr(backend, "delete_wrapped_key")
    call = dynamo.calls[0]
    assert call["TableName"] == "lucy-utopia-wrapped-keys"
    assert call["ConditionExpression"] == "attribute_not_exists(key_ref)"
    item = call["Item"]
    assert item["key_ref"] == {"S": str(UUID(int=6))}
    assert item["security_realm_id"] == {"S": str(UUID(int=4))}
    assert item["storage_epoch"] == {"N": "2"}
    assert json.loads(item["encryption_context_json"]["S"]) == _context().as_aws_context()


def test_backend_fails_closed_on_collision_and_invalid_kms_response() -> None:
    collision = ClientError(
        {"Error": {"Code": "ConditionalCheckFailedException", "Message": "collision"}},
        "PutItem",
    )
    with pytest.raises(ValueError, match="already exists"):
        _backend(dynamo=FakeDynamo(collision)).put_wrapped_key(
            key_ref=UUID(int=6),
            wrapped_key=b"wrapped",
            key_arn=KEY_ARN,
            encryption_context=_context(),
        )

    with pytest.raises(RuntimeError, match="response is invalid"):
        _backend(kms=FakeKms({"Plaintext": b"short"})).generate_data_key(
            key_arn=KEY_ARN, encryption_context=_context().as_aws_context()
        )
