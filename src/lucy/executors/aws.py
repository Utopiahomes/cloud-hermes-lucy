"""Narrow AWS adapters used by the v1.2 executor cores.

The adapter deliberately exposes no enumeration method. Every data operation is
an exact GetItem, PutItem, Update, Delete, or bounded TransactWriteItems call.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol
from uuid import UUID

from botocore.exceptions import ClientError  # type: ignore[import-untyped]

from lucy.contracts.canonical import canonical_json_bytes
from lucy.contracts.security_v1_2 import (
    AWS_DYNAMODB_TRANSACTION_ACTION_LIMIT,
    AWS_DYNAMODB_TRANSACTION_BYTES_LIMIT,
    DeletionTargetManifestV1,
    ExecutorQuotaV1,
    ExecutorReceiptV1,
    SensitiveActionPermitV2,
    SensitiveExecutionGrantV1,
)
from lucy.contracts.security_v1_3 import (
    DeletionArtifactClassV3,
    DeletionTargetManifestV2,
    DeletionTargetManifestV3,
    DeletionTargetReferenceV3,
    ExecutorReceiptV2,
    SensitiveActionPermitV3,
    SensitiveExecutionGrantV2,
)
from lucy.executors.models import WrappedKeyMaterial


class DynamoExecutorClient(Protocol):
    def get_item(self, **kwargs: Any) -> dict[str, Any]: ...

    def put_item(self, **kwargs: Any) -> dict[str, Any]: ...

    def transact_write_items(self, **kwargs: Any) -> dict[str, Any]: ...


class KmsExecutorClient(Protocol):
    def decrypt(self, **kwargs: Any) -> dict[str, Any]: ...

    def sign(self, **kwargs: Any) -> dict[str, Any]: ...


@dataclass(frozen=True)
class AwsExecutorTables:
    wrapped_keys: str
    receipts: str
    quotas: str
    intents: str | None = None

    def __post_init__(self) -> None:
        names = [self.wrapped_keys, self.receipts, self.quotas]
        if self.intents is not None:
            names.append(self.intents)
        if any(not name.strip() or len(name) > 255 for name in names):
            raise ValueError("executor DynamoDB table configuration is invalid")


class AwsExecutorBackend:
    def __init__(
        self,
        dynamodb: DynamoExecutorClient,
        kms: KmsExecutorClient,
        *,
        tables: AwsExecutorTables,
        evidence_key_arn: str | None,
        receipt_key_arn: str,
        minute_limit: int,
        day_limit: int,
        archive_registry_id: UUID | None = None,
    ) -> None:
        if minute_limit < 1 or day_limit < minute_limit:
            raise ValueError("executor quota limits are invalid")
        if not receipt_key_arn.strip():
            raise ValueError("receipt signing key ARN is required")
        self._dynamodb = dynamodb
        self._kms = kms
        self._tables = tables
        self._evidence_key_arn = evidence_key_arn
        self._receipt_key_arn = receipt_key_arn
        self._minute_limit = minute_limit
        self._day_limit = day_limit
        self._archive_registry_id = archive_registry_id

    def load_receipt(self, operation_id: UUID) -> ExecutorReceiptV1 | None:
        response = self._dynamodb.get_item(
            TableName=self._tables.receipts,
            Key={"operation_id": {"S": str(operation_id)}},
            ProjectionExpression="operation_id, receipt_json, receipt_digest",
            ConsistentRead=True,
        )
        item = response.get("Item")
        if not isinstance(item, dict):
            return None
        try:
            if item["operation_id"]["S"] != str(operation_id):
                raise ValueError("receipt operation ID changed")
            receipt = ExecutorReceiptV1.model_validate_json(item["receipt_json"]["S"])
            if item["receipt_digest"]["S"] != receipt.unsigned_digest_hex():
                raise ValueError("durable receipt digest does not match its contract")
            return receipt
        except (KeyError, TypeError, ValueError) as exc:
            raise RuntimeError("durable executor receipt is malformed") from exc

    def load_receipt_v2(self, operation_id: UUID) -> ExecutorReceiptV2 | None:
        """Load one exact realm-scoped receipt without table enumeration."""

        response = self._dynamodb.get_item(
            TableName=self._tables.receipts,
            Key={"operation_id": {"S": str(operation_id)}},
            ProjectionExpression="operation_id, receipt_json, receipt_digest",
            ConsistentRead=True,
        )
        item = response.get("Item")
        if not isinstance(item, dict):
            return None
        try:
            if item["operation_id"]["S"] != str(operation_id):
                raise ValueError("receipt operation ID changed")
            receipt = ExecutorReceiptV2.model_validate_json(item["receipt_json"]["S"])
            if item["receipt_digest"]["S"] != receipt.unsigned_digest_hex():
                raise ValueError("durable receipt digest does not match its contract")
            return receipt
        except (KeyError, TypeError, ValueError) as exc:
            raise RuntimeError("durable realm executor receipt is malformed") from exc

    def load_wrapped_key(self, key_ref: UUID) -> WrappedKeyMaterial | None:
        response = self._dynamodb.get_item(
            TableName=self._tables.wrapped_keys,
            Key={"key_ref": {"S": str(key_ref)}},
            ProjectionExpression="key_ref, ciphertext, nonce, kek_version",
            ConsistentRead=True,
        )
        item = response.get("Item")
        if not isinstance(item, dict):
            return None
        try:
            if item["key_ref"]["S"] != str(key_ref):
                raise ValueError("wrapped-key identifier changed")
            return WrappedKeyMaterial(
                ciphertext_b64=base64.b64encode(bytes(item["ciphertext"]["B"])).decode("ascii"),
                nonce_b64=base64.b64encode(bytes(item["nonce"]["B"])).decode("ascii"),
                kek_version=item["kek_version"]["S"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise RuntimeError("wrapped-key registry item is malformed") from exc

    def decrypt_data_key(
        self,
        wrapped_key: WrappedKeyMaterial,
        encryption_context: dict[str, str],
    ) -> tuple[bytes, str]:
        if self._evidence_key_arn is None:
            raise PermissionError("this executor has no evidence KMS key")
        if wrapped_key.kek_version != self._evidence_key_arn:
            raise PermissionError("wrapped key belongs to another KMS key")
        response = self._kms.decrypt(
            CiphertextBlob=base64.b64decode(wrapped_key.ciphertext_b64, validate=True),
            KeyId=self._evidence_key_arn,
            EncryptionContext=encryption_context,
        )
        plaintext = response.get("Plaintext")
        if not isinstance(plaintext, bytes) or response.get("KeyId") != self._evidence_key_arn:
            raise RuntimeError("KMS decrypt response did not match the configured evidence key")
        request_id = response.get("ResponseMetadata", {}).get("RequestId")
        if not isinstance(request_id, str) or not request_id:
            raise RuntimeError("KMS decrypt response did not contain a request ID")
        return plaintext, request_id

    def sign_receipt(self, receipt: ExecutorReceiptV1) -> ExecutorReceiptV1:
        if receipt.key_id != self._receipt_key_arn or receipt.signature:
            raise ValueError("receipt is not an unsigned contract for the configured key")
        response = self._kms.sign(
            KeyId=self._receipt_key_arn,
            Message=bytes.fromhex(receipt.unsigned_digest_hex()),
            MessageType="DIGEST",
            SigningAlgorithm="ECDSA_SHA_256",
        )
        signature = response.get("Signature")
        if not isinstance(signature, bytes):
            raise RuntimeError("KMS signing response did not contain a signature")
        if response.get("KeyId", self._receipt_key_arn) != self._receipt_key_arn:
            raise RuntimeError("KMS signing response used an unexpected key")
        if response.get("SigningAlgorithm", "ECDSA_SHA_256") != "ECDSA_SHA_256":
            raise RuntimeError("KMS signing response used an unexpected algorithm")
        return receipt.model_copy(update={"signature": base64.b64encode(signature).decode("ascii")})

    def sign_receipt_v2(self, receipt: ExecutorReceiptV2) -> ExecutorReceiptV2:
        if receipt.key_id != self._receipt_key_arn or receipt.signature:
            raise ValueError("receipt is not an unsigned V1.3 contract for the configured key")
        response = self._kms.sign(
            KeyId=self._receipt_key_arn,
            Message=bytes.fromhex(receipt.unsigned_digest_hex()),
            MessageType="DIGEST",
            SigningAlgorithm="ECDSA_SHA_256",
        )
        signature = response.get("Signature")
        if not isinstance(signature, bytes):
            raise RuntimeError("KMS signing response did not contain a signature")
        if response.get("KeyId", self._receipt_key_arn) != self._receipt_key_arn:
            raise RuntimeError("KMS signing response used an unexpected key")
        if response.get("SigningAlgorithm", "ECDSA_SHA_256") != "ECDSA_SHA_256":
            raise RuntimeError("KMS signing response used an unexpected algorithm")
        return receipt.model_copy(update={"signature": base64.b64encode(signature).decode("ascii")})

    def reserve_retrieval_quota(self, *, now: datetime, quota: ExecutorQuotaV1) -> None:
        actions = self._quota_updates(now, quota)
        self._dynamodb.transact_write_items(TransactItems=actions)

    def commit_retrieval_receipt(self, receipt: ExecutorReceiptV1) -> bool:
        try:
            self._dynamodb.put_item(
                TableName=self._tables.receipts,
                Item=self._receipt_item(receipt),
                ConditionExpression="attribute_not_exists(operation_id)",
            )
            return True
        except ClientError as exc:
            if _aws_error_code(exc) == "ConditionalCheckFailedException":
                return False
            raise

    def commit_retrieval_receipt_v2(self, receipt: ExecutorReceiptV2) -> bool:
        try:
            self._dynamodb.put_item(
                TableName=self._tables.receipts,
                Item=self._receipt_item_v2(receipt),
                ConditionExpression="attribute_not_exists(operation_id)",
            )
            return True
        except ClientError as exc:
            if _aws_error_code(exc) == "ConditionalCheckFailedException":
                return False
            raise

    def commit_deletion(
        self,
        *,
        permit: SensitiveActionPermitV2,
        grant: SensitiveExecutionGrantV1,
        manifest: DeletionTargetManifestV1,
        receipt: ExecutorReceiptV1,
        transaction_token: str,
        now: datetime,
        quota: ExecutorQuotaV1,
    ) -> bool:
        if self._tables.intents is None:
            raise RuntimeError("deletion executor has no immutable intent table")
        if len(transaction_token) > 36:
            raise ValueError("DynamoDB client request token exceeds its hard limit")
        manifest_json = canonical_json_bytes(manifest).decode("utf-8")
        permit_json = canonical_json_bytes(permit).decode("utf-8")
        grant_json = canonical_json_bytes(grant).decode("utf-8")
        actions: list[dict[str, Any]] = [
            {
                "Put": {
                    "TableName": self._tables.intents,
                    "Item": {
                        "operation_id": {"S": str(receipt.operation_id)},
                        "permit_id": {"S": str(receipt.permit_id)},
                        "manifest_id": {"S": str(manifest.manifest_id)},
                        "manifest_digest": {"S": manifest.unsigned_digest_hex()},
                        "manifest_json": {"S": manifest_json},
                        "permit_digest": {"S": permit.unsigned_digest_hex()},
                        "permit_json": {"S": permit_json},
                        "grant_digest": {"S": grant.unsigned_digest_hex()},
                        "grant_json": {"S": grant_json},
                        "accepted_at": {"S": _utc_text(now)},
                    },
                    "ConditionExpression": "attribute_not_exists(operation_id)",
                }
            },
            {
                "Put": {
                    "TableName": self._tables.receipts,
                    "Item": self._receipt_item(receipt),
                    "ConditionExpression": "attribute_not_exists(operation_id)",
                }
            },
            *self._quota_updates(now, quota),
        ]
        actions.extend(
            {
                "Delete": {
                    "TableName": self._tables.wrapped_keys,
                    "Key": {"key_ref": {"S": str(target.key_ref)}},
                    "ConditionExpression": "attribute_exists(key_ref)",
                }
            }
            for target in manifest.targets
        )
        if len(actions) > AWS_DYNAMODB_TRANSACTION_ACTION_LIMIT:
            raise ValueError("deletion transaction exceeds the AWS action limit")
        serialized = json.dumps(actions, separators=(",", ":"), sort_keys=True).encode("utf-8")
        if len(serialized) > AWS_DYNAMODB_TRANSACTION_BYTES_LIMIT:
            raise ValueError("deletion transaction exceeds the AWS byte limit")
        try:
            self._dynamodb.transact_write_items(
                TransactItems=actions,
                ClientRequestToken=transaction_token,
            )
            return True
        except ClientError as exc:
            if _aws_error_code(exc) == "TransactionCanceledException":
                return False
            raise

    def commit_deletion_v2(
        self,
        *,
        permit: SensitiveActionPermitV3,
        grant: SensitiveExecutionGrantV2,
        manifest: DeletionTargetManifestV2,
        receipt: ExecutorReceiptV2,
        transaction_token: str,
        now: datetime,
        quota: ExecutorQuotaV1,
    ) -> bool:
        """Commit one realm's content-free proof and exact wrapped-key removals."""

        if self._tables.intents is None:
            raise RuntimeError("deletion executor has no immutable intent table")
        if len(transaction_token) > 36:
            raise ValueError("DynamoDB client request token exceeds its hard limit")
        actions: list[dict[str, Any]] = [
            {
                "Put": {
                    "TableName": self._tables.intents,
                    "Item": {
                        "operation_id": {"S": str(receipt.operation_id)},
                        "permit_id": {"S": str(receipt.permit_id)},
                        "security_realm_id": {"S": str(receipt.target_scope.security_realm_id)},
                        "manifest_id": {"S": str(manifest.manifest_id)},
                        "manifest_digest": {"S": manifest.unsigned_digest_hex()},
                        "manifest_json": {
                            "S": canonical_json_bytes(manifest).decode("utf-8")
                        },
                        "permit_digest": {"S": permit.unsigned_digest_hex()},
                        "permit_json": {"S": canonical_json_bytes(permit).decode("utf-8")},
                        "grant_digest": {"S": grant.unsigned_digest_hex()},
                        "grant_json": {"S": canonical_json_bytes(grant).decode("utf-8")},
                        "accepted_at": {"S": _utc_text(now)},
                    },
                    "ConditionExpression": "attribute_not_exists(operation_id)",
                }
            },
            {
                "Put": {
                    "TableName": self._tables.receipts,
                    "Item": self._receipt_item_v2(receipt),
                    "ConditionExpression": "attribute_not_exists(operation_id)",
                }
            },
            *self._quota_updates(now, quota),
        ]
        actions.extend(
            {
                "Delete": {
                    "TableName": self._tables.wrapped_keys,
                    "Key": {"key_ref": {"S": str(target.wrapped_key_ref)}},
                    "ConditionExpression": "attribute_exists(key_ref)",
                }
            }
            for target in manifest.targets
            if target.wrapped_key_ref is not None
        )
        if len(actions) > AWS_DYNAMODB_TRANSACTION_ACTION_LIMIT:
            raise ValueError("deletion transaction exceeds the AWS action limit")
        serialized = json.dumps(actions, separators=(",", ":"), sort_keys=True).encode("utf-8")
        if len(serialized) > AWS_DYNAMODB_TRANSACTION_BYTES_LIMIT:
            raise ValueError("deletion transaction exceeds the AWS byte limit")
        try:
            self._dynamodb.transact_write_items(
                TransactItems=actions,
                ClientRequestToken=transaction_token,
            )
            return True
        except ClientError as exc:
            if _aws_error_code(exc) == "TransactionCanceledException":
                return False
            raise

    def commit_deletion_v3(
        self,
        *,
        permit: SensitiveActionPermitV3,
        grant: SensitiveExecutionGrantV2,
        manifest: DeletionTargetManifestV3,
        receipt: ExecutorReceiptV2,
        transaction_token: str,
        now: datetime,
        quota: ExecutorQuotaV1,
    ) -> bool:
        """Atomically tombstone each exact key while retaining authenticated identity."""

        if self._tables.intents is None:
            raise RuntimeError("deletion executor has no immutable intent table")
        if self._archive_registry_id is None:
            raise RuntimeError("deletion executor has no archive registry identity")
        if len(transaction_token) > 36:
            raise ValueError("DynamoDB client request token exceeds its hard limit")
        actions: list[dict[str, Any]] = [
            {
                "Put": {
                    "TableName": self._tables.intents,
                    "Item": {
                        "operation_id": {"S": str(receipt.operation_id)},
                        "permit_id": {"S": str(receipt.permit_id)},
                        "security_realm_id": {
                            "S": str(receipt.target_scope.security_realm_id)
                        },
                        "manifest_id": {"S": str(manifest.manifest_id)},
                        "manifest_version": {"N": "3"},
                        "manifest_digest": {"S": manifest.unsigned_digest_hex()},
                        "manifest_json": {
                            "S": canonical_json_bytes(manifest).decode("utf-8")
                        },
                        "permit_digest": {"S": permit.unsigned_digest_hex()},
                        "permit_json": {"S": canonical_json_bytes(permit).decode("utf-8")},
                        "grant_digest": {"S": grant.unsigned_digest_hex()},
                        "grant_json": {"S": canonical_json_bytes(grant).decode("utf-8")},
                        "accepted_at": {"S": _utc_text(now)},
                    },
                    "ConditionExpression": "attribute_not_exists(operation_id)",
                }
            },
            {
                "Put": {
                    "TableName": self._tables.receipts,
                    "Item": self._receipt_item_v2(receipt),
                    "ConditionExpression": "attribute_not_exists(operation_id)",
                }
            },
            *self._quota_updates(now, quota),
        ]
        key_targets: dict[UUID, tuple[DeletionTargetReferenceV3, str]] = {}
        for target in manifest.targets:
            if target.wrapped_key_ref is None:
                continue
            if (
                target.artifact_class
                == DeletionArtifactClassV3.MEMORY_IMPORT_PROVIDER_OUTCOME
                and target.key_registry_id != self._archive_registry_id
            ):
                raise ValueError("provider outcome belongs to another key registry")
            digest = _wrapped_key_tombstone_digest_v3(
                target, registry_id=self._archive_registry_id
            )
            prior = key_targets.get(target.wrapped_key_ref)
            if prior is not None and prior[1] != digest:
                raise ValueError("one wrapped key has conflicting V3 target identities")
            key_targets[target.wrapped_key_ref] = (target, digest)
        for target, digest in key_targets.values():
            actions.append(
                {
                    "Update": {
                        "TableName": self._tables.wrapped_keys,
                        "Key": {"key_ref": {"S": str(target.wrapped_key_ref)}},
                        "UpdateExpression": (
                            "REMOVE ciphertext, nonce, kek_version "
                            "SET tombstone_digest=:digest, tombstone_artifact_class=:class, "
                            "tombstone_artifact_id=:artifact, tombstone_artifact_version=:version, "
                            "tombstone_representation_id=:representation, "
                            "tombstone_registry_id=:registry"
                        ),
                        "ConditionExpression": (
                            "(attribute_exists(key_ref) AND attribute_exists(ciphertext) "
                            "AND attribute_exists(nonce) AND attribute_exists(kek_version) "
                            "AND attribute_not_exists(tombstone_digest)) OR "
                            "(attribute_exists(key_ref) AND tombstone_digest=:digest "
                            "AND tombstone_artifact_class=:class "
                            "AND tombstone_artifact_id=:artifact "
                            "AND tombstone_artifact_version=:version "
                            "AND tombstone_representation_id=:representation "
                            "AND tombstone_registry_id=:registry)"
                        ),
                        "ExpressionAttributeValues": {
                            ":digest": {"S": digest},
                            ":class": {"S": target.artifact_class.value},
                            ":artifact": {"S": str(target.artifact_id)},
                            ":version": {"N": str(target.artifact_version)},
                            ":representation": {"S": str(target.representation_id)},
                            ":registry": {"S": str(self._archive_registry_id)},
                        },
                    }
                }
            )
        if len(actions) > AWS_DYNAMODB_TRANSACTION_ACTION_LIMIT:
            raise ValueError("deletion transaction exceeds the AWS action limit")
        serialized = json.dumps(actions, separators=(",", ":"), sort_keys=True).encode("utf-8")
        if len(serialized) > AWS_DYNAMODB_TRANSACTION_BYTES_LIMIT:
            raise ValueError("deletion transaction exceeds the AWS byte limit")
        try:
            self._dynamodb.transact_write_items(
                TransactItems=actions,
                ClientRequestToken=transaction_token,
            )
            return True
        except ClientError as exc:
            if _aws_error_code(exc) == "TransactionCanceledException":
                return False
            raise

    def _receipt_item(self, receipt: ExecutorReceiptV1) -> dict[str, dict[str, str]]:
        return {
            "operation_id": {"S": str(receipt.operation_id)},
            "action": {"S": receipt.action.value},
            "permit_id": {"S": str(receipt.permit_id)},
            "grant_id": {"S": str(receipt.execution_grant_id)},
            "package_digest": {"S": receipt.package_digest},
            "receipt_digest": {"S": receipt.unsigned_digest_hex()},
            "receipt_json": {"S": canonical_json_bytes(receipt).decode("utf-8")},
            "completed_at": {"S": _utc_text(receipt.completed_at)},
        }

    def _receipt_item_v2(self, receipt: ExecutorReceiptV2) -> dict[str, dict[str, str]]:
        return {
            "operation_id": {"S": str(receipt.operation_id)},
            "action": {"S": receipt.action.value},
            "permit_id": {"S": str(receipt.permit_id)},
            "grant_id": {"S": str(receipt.execution_grant_id)},
            "security_realm_id": {"S": str(receipt.target_scope.security_realm_id)},
            "storage_epoch": {"N": str(receipt.target_scope.storage_epoch)},
            "package_digest": {"S": receipt.package_digest},
            "receipt_digest": {"S": receipt.unsigned_digest_hex()},
            "receipt_json": {"S": canonical_json_bytes(receipt).decode("utf-8")},
            "completed_at": {"S": _utc_text(receipt.completed_at)},
        }

    def _quota_updates(
        self,
        now: datetime,
        quota: ExecutorQuotaV1,
    ) -> list[dict[str, Any]]:
        action = quota.action.value
        utc = now.astimezone(UTC)
        minute = utc.strftime("%Y%m%d%H%M")
        day = utc.strftime("%Y%m%d")
        return [
            self._quota_update(
                key=f"{action}:minute:{minute}",
                limit=self._minute_limit,
                expires_at=utc + timedelta(days=2),
            ),
            self._quota_update(
                key=f"{action}:day:{day}",
                limit=self._day_limit,
                expires_at=utc + timedelta(days=3),
            ),
        ]

    def _quota_update(self, *, key: str, limit: int, expires_at: datetime) -> dict[str, Any]:
        return {
            "Update": {
                "TableName": self._tables.quotas,
                "Key": {"quota_key": {"S": key}},
                "UpdateExpression": (
                    "SET #count = if_not_exists(#count,:zero) + :one, expires_at = :expires"
                ),
                "ConditionExpression": "attribute_not_exists(#count) OR #count < :limit",
                "ExpressionAttributeNames": {"#count": "request_count"},
                "ExpressionAttributeValues": {
                    ":zero": {"N": "0"},
                    ":one": {"N": "1"},
                    ":limit": {"N": str(limit)},
                    ":expires": {"N": str(int(expires_at.timestamp()))},
                },
            }
        }


def _aws_error_code(exc: ClientError) -> str:
    value = exc.response.get("Error", {}).get("Code", "")
    return value if isinstance(value, str) else ""


def _wrapped_key_tombstone_digest_v3(
    target: DeletionTargetReferenceV3, *, registry_id: UUID
) -> str:
    """Commit the stable key identity; root evidence is deliberately excluded."""

    stable = {
        "artifact_class": target.artifact_class.value,
        "artifact_id": str(target.artifact_id),
        "artifact_version": target.artifact_version,
        "disposition": target.disposition.value,
        "representation_id": str(target.representation_id),
        "wrapped_key_ref": str(target.wrapped_key_ref),
        "key_registry_id": str(registry_id),
    }
    return hashlib.sha256(
        b"lucy:wrapped-key-tombstone:v3\0" + canonical_json_bytes(stable)
    ).hexdigest()


def _utc_text(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
