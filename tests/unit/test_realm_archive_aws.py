from __future__ import annotations

import base64
import json
from typing import Any
from uuid import UUID

import pytest
from botocore.exceptions import ClientError

from lucy.contracts.security_v1_3 import KmsEncryptionContextV2, OriginScopeV1
from lucy.realm_archive import (
    RealmArchiveEncryptor,
    RealmArchiveEnvelopeV1,
    RealmArchiveIdentityV1,
)
from lucy.realm_archive_aws import AwsRealmArchiveBackend, realm_archive_from_environment

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
    def __init__(
        self,
        error: ClientError | None = None,
        get_response: dict[str, Any] | None = None,
    ) -> None:
        self.calls: list[dict[str, Any]] = []
        self.error = error
        self.get_response = get_response or {}

    def put_item(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return {}

    def get_item(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        return self.get_response


def _backend(
    kms: FakeKms | None = None, dynamo: FakeDynamo | None = None
) -> AwsRealmArchiveBackend:
    return AwsRealmArchiveBackend(
        kms or FakeKms(),
        dynamo or FakeDynamo(),
        evidence_key_arn=KEY_ARN,
        wrapped_key_table="lucy-utopia-wrapped-keys",
    )


def _encrypt(backend: AwsRealmArchiveBackend) -> RealmArchiveEnvelopeV1:
    return RealmArchiveEncryptor(
        backend,
        RealmArchiveIdentityV1(
            target_scope=_scope(),
            evidence_key_arn=KEY_ARN,
            record_version=1,
        ),
        commitment_key=b"c" * 32,
    ).encrypt(
        evidence_id=UUID(int=5),
        representation_id=UUID(int=6),
        key_ref=UUID(int=7),
        plaintext=b"synthetic",
        authenticated_header=b"header",
        request_commitment="a" * 64,
    )


def _scope() -> OriginScopeV1:
    context = _context()
    return OriginScopeV1(
        tenant_account_id=context.tenant_account_id,
        node_id=context.node_id,
        node_tenure_id=context.node_tenure_id,
        tenure_epoch=context.tenure_epoch,
        security_realm_id=context.security_realm_id,
        storage_epoch=context.storage_epoch,
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
    envelope = _encrypt(backend)
    assert not hasattr(backend, "get_wrapped_key")
    assert not hasattr(backend, "delete_wrapped_key")
    call = dynamo.calls[-1]
    assert call["TableName"] == "lucy-utopia-wrapped-keys"
    assert call["ConditionExpression"] == "attribute_not_exists(key_ref)"
    item = call["Item"]
    assert item["key_ref"] == {"S": str(UUID(int=7))}
    assert item["security_realm_id"] == {"S": str(UUID(int=4))}
    assert item["storage_epoch"] == {"N": "2"}
    assert json.loads(item["encryption_context_json"]["S"]) == _context().as_aws_context()
    replay = _backend(dynamo=FakeDynamo(get_response={"Item": item})).load_archive_envelope(
        UUID(int=7)
    )
    assert replay == envelope


def test_backend_fails_closed_on_collision_and_invalid_kms_response() -> None:
    collision = ClientError(
        {"Error": {"Code": "ConditionalCheckFailedException", "Message": "collision"}},
        "PutItem",
    )
    with pytest.raises(ValueError, match="already exists"):
        _encrypt(_backend(dynamo=FakeDynamo(collision)))

    with pytest.raises(RuntimeError, match="response is invalid"):
        _backend(kms=FakeKms({"Plaintext": b"short"})).generate_data_key(
            key_arn=KEY_ARN, encryption_context=_context().as_aws_context()
        )


def _environment() -> dict[str, str]:
    context = _context()
    scope = {
        "tenant_account_id": str(context.tenant_account_id),
        "node_id": str(context.node_id),
        "node_tenure_id": str(context.node_tenure_id),
        "tenure_epoch": context.tenure_epoch,
        "security_realm_id": str(context.security_realm_id),
        "storage_epoch": context.storage_epoch,
    }
    return {
        "LUCY_ARCHIVE_BACKEND": "aws-kms-dynamodb-v13",
        "AWS_REGION": "us-east-1",
        "LUCY_AWS_ACCOUNT_ID": ACCOUNT,
        "LUCY_AWS_EVIDENCE_KEY_ARN": KEY_ARN,
        "LUCY_AWS_WRAPPED_KEY_TABLE": "lucy-utopia-wrapped-keys",
        "LUCY_V13_TARGET_SCOPE_JSON": json.dumps(scope),
        "LUCY_ARCHIVE_RECORD_VERSION": "1",
        "LUCY_ARCHIVE_COMMITMENT_KEY_B64": base64.b64encode(b"c" * 32).decode(),
    }


def test_environment_factory_pins_region_account_scope_and_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clients = {"kms": FakeKms(), "dynamodb": FakeDynamo()}
    monkeypatch.setattr(
        "lucy.realm_archive_aws.boto3.client",
        lambda service, **kwargs: clients[service],
    )
    encryptor = realm_archive_from_environment(_environment())
    result = encryptor.encrypt(
        evidence_id=UUID(int=5),
        representation_id=UUID(int=6),
        key_ref=UUID(int=7),
        plaintext=b"synthetic",
        authenticated_header=b"header",
        request_commitment="a" * 64,
    )
    assert result.wrapper_binding.wrapping_scope.security_realm_id == UUID(int=4)
    assert len(clients["kms"].calls) == 1
    assert len(clients["dynamodb"].calls) == 1


@pytest.mark.parametrize(
    ("name", "value"),
    (
        ("LUCY_ARCHIVE_BACKEND", "aws-kms-dynamodb"),
        ("AWS_REGION", "us-west-2"),
        ("LUCY_AWS_ACCOUNT_ID", "999"),
        ("LUCY_AWS_EVIDENCE_KEY_ARN", "alias/lucy"),
        ("LUCY_ARCHIVE_RECORD_VERSION", "0"),
        ("LUCY_ARCHIVE_COMMITMENT_KEY_B64", "not-base64"),
    ),
)
def test_environment_factory_rejects_invalid_deployment_binding_before_aws(
    monkeypatch: pytest.MonkeyPatch, name: str, value: str
) -> None:
    monkeypatch.setattr(
        "lucy.realm_archive_aws.boto3.client",
        lambda *_args, **_kwargs: pytest.fail("AWS client must not be constructed"),
    )
    environment = _environment()
    environment[name] = value
    with pytest.raises(ValueError):
        realm_archive_from_environment(environment)
