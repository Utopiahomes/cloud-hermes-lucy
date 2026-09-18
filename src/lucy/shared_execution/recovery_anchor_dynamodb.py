"""DynamoDB persistence for Tiamat's signed external recovery anchor.

PostgreSQL remains the execution/accounting system of record. DynamoDB stores only the exact
signed recovery-authority bytes and performs an atomic predecessor compare-and-swap. Unsigned
index attributes are never treated as authority.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any, Protocol

import boto3  # type: ignore[import-untyped]
from botocore.exceptions import BotoCoreError, ClientError  # type: ignore[import-untyped]

from lucy.shared_execution.recovery_anchor import (
    RecoveryAnchorKey,
    RecoveryAnchorRejected,
    VerifiedAnchorTransition,
    validate_anchor_successor,
)


class AnchorTransitionDecoder(Protocol):
    """Authenticate exact stored bytes and reconstruct their verified transition."""

    def __call__(
        self, exact_transition_jws: bytes, exact_witness_jws: bytes
    ) -> VerifiedAnchorTransition: ...


class DynamoDbClient(Protocol):
    def get_item(self, **kwargs: Any) -> dict[str, Any]: ...

    def put_item(self, **kwargs: Any) -> dict[str, Any]: ...


class DynamoDbExternalRecoveryAnchor:
    """One-history DynamoDB adapter using strong reads and conditional writes."""

    def __init__(
        self,
        *,
        client: DynamoDbClient,
        table_name: str,
        decode_transition: AnchorTransitionDecoder,
    ) -> None:
        if not table_name:
            raise ValueError("recovery anchor table name is required")
        self._client = client
        self._table_name = table_name
        self._decode_transition = decode_transition

    def read(self, key: RecoveryAnchorKey) -> VerifiedAnchorTransition:
        try:
            response = self._client.get_item(
                TableName=self._table_name,
                Key={"anchor_key": {"S": self._storage_key(key)}},
                ConsistentRead=True,
            )
        except (BotoCoreError, ClientError) as exc:
            raise RecoveryAnchorRejected("recovery_anchor_unavailable") from exc
        item = response.get("Item")
        if not isinstance(item, dict):
            raise RecoveryAnchorRejected("recovery_anchor_unavailable")
        transition = self._decode_item(item)
        if transition.witness.identity.key != key:
            raise RecoveryAnchorRejected("recovery_anchor_identity_mismatch")
        return transition

    def install(
        self,
        transition: VerifiedAnchorTransition,
        *,
        expected_transition_sha256: str | None,
        now: datetime,
    ) -> VerifiedAnchorTransition:
        if now.tzinfo is None:
            raise ValueError("recovery time must be aware")
        if not transition.witness.valid_at(now):
            raise RecoveryAnchorRejected("recovery_witness_not_current")

        # Do not accept a caller-constructed object unless the exact bytes authenticate to it.
        decoded = self._decode_transition(transition.exact_jws, transition.witness.exact_jws)
        if decoded != transition:
            raise RecoveryAnchorRejected("recovery_anchor_signed_bytes_mismatch")

        key = transition.witness.identity.key
        values: dict[str, dict[str, str]] = {}
        if expected_transition_sha256 is None:
            if (
                transition.transition_version != 1
                or transition.previous_transition_sha256 is not None
            ):
                raise RecoveryAnchorRejected("recovery_anchor_compare_failed")
            condition = "attribute_not_exists(#anchor_key)"
            expression_names = {"#anchor_key": "anchor_key"}
        else:
            if transition.previous_transition_sha256 != expected_transition_sha256:
                raise RecoveryAnchorRejected("recovery_anchor_transition_chain_invalid")
            previous = self.read(key)
            if previous.exact_sha256 != expected_transition_sha256:
                raise RecoveryAnchorRejected("recovery_anchor_compare_failed")
            validate_anchor_successor(previous, transition)
            condition = (
                "#transition_sha256 = :expected_digest AND "
                "#transition_version = :expected_version"
            )
            expression_names = {
                "#transition_sha256": "transition_sha256",
                "#transition_version": "transition_version",
            }
            values = {
                ":expected_digest": {"S": expected_transition_sha256},
                ":expected_version": {"N": str(previous.transition_version)},
            }

        item = {
            "anchor_key": {"S": self._storage_key(key)},
            "transition_sha256": {"S": transition.exact_sha256},
            "transition_version": {"N": str(transition.transition_version)},
            "transition_jws": {"B": transition.exact_jws},
            "witness_jws": {"B": transition.witness.exact_jws},
        }
        request: dict[str, Any] = {
            "TableName": self._table_name,
            "Item": item,
            "ConditionExpression": condition,
            "ExpressionAttributeNames": expression_names,
        }
        if values:
            request["ExpressionAttributeValues"] = values
        try:
            self._client.put_item(**request)
        except ClientError as exc:
            code = str(exc.response.get("Error", {}).get("Code", ""))
            if code == "ConditionalCheckFailedException":
                raise RecoveryAnchorRejected("recovery_anchor_compare_failed") from exc
            raise RecoveryAnchorRejected("recovery_anchor_unavailable") from exc
        except BotoCoreError as exc:
            raise RecoveryAnchorRejected("recovery_anchor_unavailable") from exc
        return transition

    def _decode_item(self, item: dict[str, Any]) -> VerifiedAnchorTransition:
        try:
            transition_jws = bytes(item["transition_jws"]["B"])
            witness_jws = bytes(item["witness_jws"]["B"])
            stored_digest = str(item["transition_sha256"]["S"])
            stored_version = int(item["transition_version"]["N"])
        except (KeyError, TypeError, ValueError) as exc:
            raise RecoveryAnchorRejected("recovery_anchor_record_invalid") from exc
        transition = self._decode_transition(transition_jws, witness_jws)
        if (
            transition.exact_sha256 != stored_digest
            or transition.transition_version != stored_version
        ):
            raise RecoveryAnchorRejected("recovery_anchor_record_invalid")
        return transition

    @staticmethod
    def _storage_key(key: RecoveryAnchorKey) -> str:
        return f"ENV#{key.environment}#LEDGER#{key.ledger_id}"


_TABLE_NAME = re.compile(r"^[A-Za-z0-9_.-]{3,255}$")
_REGION = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z]+-\d+$")


def dynamodb_recovery_anchor_from_environment(
    decode_transition: AnchorTransitionDecoder,
    *,
    environment: Mapping[str, str] | None = None,
    client_factory: Any | None = None,
) -> DynamoDbExternalRecoveryAnchor:
    """Build the deployment adapter without accepting credentials as application settings."""

    values = os.environ if environment is None else environment
    table_name = values.get("TIAMAT_RECOVERY_ANCHOR_TABLE", "")
    region = values.get("AWS_REGION", "")
    if _TABLE_NAME.fullmatch(table_name) is None:
        raise ValueError("TIAMAT_RECOVERY_ANCHOR_TABLE is invalid")
    if _REGION.fullmatch(region) is None:
        raise ValueError("AWS_REGION is invalid")
    factory = boto3.client if client_factory is None else client_factory
    client = factory("dynamodb", region_name=region)
    return DynamoDbExternalRecoveryAnchor(
        client=client,
        table_name=table_name,
        decode_transition=decode_transition,
    )
