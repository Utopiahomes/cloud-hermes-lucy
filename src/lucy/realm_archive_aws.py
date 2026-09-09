"""Exact AWS effects for the V1.3 encryption-only realm archive."""

from __future__ import annotations

import base64
import json
import os
import re
from collections.abc import Mapping
from typing import Any, Protocol, cast
from uuid import UUID

import boto3  # type: ignore[import-untyped]
from botocore.exceptions import ClientError  # type: ignore[import-untyped]
from pydantic import ValidationError

from lucy.contracts.canonical import canonical_sha256
from lucy.contracts.security_v1_3 import OriginScopeV1
from lucy.realm_archive import (
    GeneratedDataKeyV1,
    RealmArchiveEncryptor,
    RealmArchiveEnvelopeV1,
    RealmArchiveIdentityV1,
)

_TABLE_NAME = re.compile(r"[A-Za-z0-9_.-]{3,255}\Z")
_ACCOUNT_ID = re.compile(r"[0-9]{12}\Z")


class KmsArchiveClient(Protocol):
    def generate_data_key(self, **kwargs: Any) -> dict[str, Any]: ...


class DynamoArchiveClient(Protocol):
    def put_item(self, **kwargs: Any) -> dict[str, Any]: ...

    def get_item(self, **kwargs: Any) -> dict[str, Any]: ...


class AwsRealmArchiveBackend:
    """Generate and store one exact wrapped DEK; no read/decrypt/delete surface."""

    def __init__(
        self,
        kms: KmsArchiveClient,
        dynamodb: DynamoArchiveClient,
        *,
        evidence_key_arn: str,
        wrapped_key_table: str,
    ) -> None:
        if not evidence_key_arn.strip():
            raise ValueError("realm archive evidence key ARN is required")
        if _TABLE_NAME.fullmatch(wrapped_key_table) is None:
            raise ValueError("realm archive wrapped-key table name is invalid")
        self._kms = kms
        self._dynamodb = dynamodb
        self._evidence_key_arn = evidence_key_arn
        self._wrapped_key_table = wrapped_key_table

    @classmethod
    def from_environment(cls) -> AwsRealmArchiveBackend:
        region = os.environ.get("AWS_REGION", "").strip()
        if not region:
            raise ValueError("AWS_REGION is required")
        return cls(
            cast(KmsArchiveClient, boto3.client("kms", region_name=region)),
            cast(DynamoArchiveClient, boto3.client("dynamodb", region_name=region)),
            evidence_key_arn=os.environ.get("LUCY_AWS_EVIDENCE_KEY_ARN", "").strip(),
            wrapped_key_table=os.environ.get("LUCY_AWS_WRAPPED_KEY_TABLE", "").strip(),
        )

    def generate_data_key(
        self, *, key_arn: str, encryption_context: dict[str, str]
    ) -> GeneratedDataKeyV1:
        if key_arn != self._evidence_key_arn:
            raise PermissionError("realm archive requested an unconfigured evidence key")
        response = self._kms.generate_data_key(
            KeyId=self._evidence_key_arn,
            KeySpec="AES_256",
            EncryptionContext=encryption_context,
        )
        plaintext = response.get("Plaintext")
        ciphertext = response.get("CiphertextBlob")
        request_id = response.get("ResponseMetadata", {}).get("RequestId")
        response_key = response.get("KeyId")
        if (
            not isinstance(plaintext, bytes)
            or not isinstance(ciphertext, bytes)
            or not isinstance(request_id, str)
            or not request_id
            or response_key != self._evidence_key_arn
        ):
            raise RuntimeError("KMS generate-data-key response is invalid")
        return GeneratedDataKeyV1(plaintext, ciphertext, response_key, request_id)

    def load_archive_envelope(self, key_ref: UUID) -> RealmArchiveEnvelopeV1 | None:
        response = self._dynamodb.get_item(
            TableName=self._wrapped_key_table,
            Key={"key_ref": {"S": str(key_ref)}},
            ProjectionExpression=(
                "key_ref, envelope_json, envelope_digest, kek_version, security_realm_id"
            ),
            ConsistentRead=True,
        )
        item = response.get("Item")
        if not isinstance(item, dict):
            return None
        try:
            envelope = RealmArchiveEnvelopeV1.model_validate_json(
                item["envelope_json"]["S"]
            )
            if (
                item["key_ref"]["S"] != str(key_ref)
                or envelope.wrapper_binding.wrapped_key_ref != key_ref
                or item["envelope_digest"]["S"]
                != canonical_sha256(envelope.model_dump(mode="python"))
                or item["kek_version"]["S"] != self._evidence_key_arn
                or item["security_realm_id"]["S"]
                != str(envelope.wrapper_binding.wrapping_scope.security_realm_id)
            ):
                raise ValueError("realm archive envelope metadata changed")
            return envelope
        except (KeyError, TypeError, ValueError) as exc:
            raise RuntimeError("durable realm archive envelope is malformed") from exc

    def put_archive_envelope(
        self,
        *,
        envelope: RealmArchiveEnvelopeV1,
        wrapped_key: bytes,
        key_arn: str,
    ) -> None:
        if key_arn != self._evidence_key_arn or not wrapped_key:
            raise PermissionError("realm archive wrapped key is outside its configured key")
        context = envelope.wrapper_binding.encryption_context
        key_ref = envelope.wrapper_binding.wrapped_key_ref
        item = {
            "key_ref": {"S": str(key_ref)},
            "ciphertext": {"B": wrapped_key},
            "nonce": {"B": b"kms"},
            "kek_version": {"S": self._evidence_key_arn},
            "tenant_account_id": {"S": str(context.tenant_account_id)},
            "node_id": {"S": str(context.node_id)},
            "node_tenure_id": {"S": str(context.node_tenure_id)},
            "tenure_epoch": {"N": str(context.tenure_epoch)},
            "security_realm_id": {"S": str(context.security_realm_id)},
            "storage_epoch": {"N": str(context.storage_epoch)},
            "evidence_id": {"S": str(context.evidence_id)},
            "encryption_context_json": {
                "S": json.dumps(
                    context.as_aws_context(),
                    separators=(",", ":"),
                    sort_keys=True,
                )
            },
            "envelope_json": {"S": envelope.model_dump_json()},
            "envelope_digest": {
                "S": canonical_sha256(envelope.model_dump(mode="python"))
            },
        }
        try:
            self._dynamodb.put_item(
                TableName=self._wrapped_key_table,
                Item=item,
                ConditionExpression="attribute_not_exists(key_ref)",
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                raise ValueError("realm archive wrapped-key reference already exists") from exc
            raise


def realm_archive_from_environment(
    environment: Mapping[str, str] | None = None,
) -> RealmArchiveEncryptor:
    """Construct one deployment-owned realm encryptor without request-selected scope."""

    values = os.environ if environment is None else environment
    if values.get("LUCY_ARCHIVE_BACKEND", "").strip() != "aws-kms-dynamodb-v13":
        raise ValueError("V1.3 realm archive backend is not selected")
    region = values.get("AWS_REGION", "").strip()
    account_id = values.get("LUCY_AWS_ACCOUNT_ID", "").strip()
    key_arn = values.get("LUCY_AWS_EVIDENCE_KEY_ARN", "").strip()
    key_match = re.fullmatch(
        rf"arn:aws:kms:{re.escape(region)}:{re.escape(account_id)}:key/[0-9a-f-]{{36}}",
        key_arn,
    )
    if (
        region != "us-east-1"
        or _ACCOUNT_ID.fullmatch(account_id) is None
        or key_match is None
    ):
        raise ValueError("V1.3 realm archive AWS boundary is invalid")
    try:
        scope = OriginScopeV1.model_validate_json(
            _required(values, "LUCY_V13_TARGET_SCOPE_JSON")
        )
        record_version = int(_required(values, "LUCY_ARCHIVE_RECORD_VERSION"))
        commitment_key = base64.b64decode(
            _required(values, "LUCY_ARCHIVE_COMMITMENT_KEY_B64"), validate=True
        )
    except (ValidationError, ValueError) as exc:
        raise ValueError("V1.3 realm archive identity configuration is invalid") from exc
    if record_version < 1 or len(commitment_key) != 32:
        raise ValueError("V1.3 realm archive cryptographic configuration is invalid")

    kms = cast(KmsArchiveClient, boto3.client("kms", region_name=region))
    dynamodb = cast(DynamoArchiveClient, boto3.client("dynamodb", region_name=region))
    backend = AwsRealmArchiveBackend(
        kms,
        dynamodb,
        evidence_key_arn=key_arn,
        wrapped_key_table=_required(values, "LUCY_AWS_WRAPPED_KEY_TABLE"),
    )
    return RealmArchiveEncryptor(
        backend,
        RealmArchiveIdentityV1(
            target_scope=scope,
            evidence_key_arn=key_arn,
            record_version=record_version,
        ),
        commitment_key=commitment_key,
    )


def _required(values: Mapping[str, str], name: str) -> str:
    value = values.get(name, "").strip()
    if not value:
        raise ValueError(f"required V1.3 realm archive configuration is missing: {name}")
    return value
