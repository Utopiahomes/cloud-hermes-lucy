"""DynamoDB adapter for independent R1 authority and cost recovery journals."""

from __future__ import annotations

import json
import os
import re
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from typing import Protocol, cast
from uuid import UUID

import boto3  # type: ignore[import-untyped]
from botocore.exceptions import BotoCoreError, ClientError  # type: ignore[import-untyped]
from pydantic import ValidationError

from lucy.recovery_journal import (
    RecoveryAppendAcknowledgementV1,
    RecoveryJournalError,
    RecoveryJournalEventV1,
    RecoveryJournalHeadV1,
    RecoveryStreamBindingV1,
    RecoveryStreamKind,
    RecoveryWriterPauseV1,
    advance_recovery_head,
)

_TABLE_NAME = re.compile(r"[A-Za-z0-9_.-]{3,255}\Z")
_GENESIS = "0" * 64


class DynamoRecoveryClient(Protocol):
    def get_item(self, **kwargs: object) -> dict[str, object]: ...

    def put_item(self, **kwargs: object) -> dict[str, object]: ...

    def transact_write_items(self, **kwargs: object) -> dict[str, object]: ...


class AwsDynamoRecoveryJournal:
    """Exact conditional journal operations over one deployment-pinned table.

    The table and genesis head are provisioned outside this adapter. It never
    creates a missing stream, scans, queries, or accepts a caller-selected scope.
    """

    def __init__(
        self,
        client: DynamoRecoveryClient,
        *,
        table_name: str,
        binding: RecoveryStreamBindingV1,
    ) -> None:
        if _TABLE_NAME.fullmatch(table_name) is None:
            raise ValueError("invalid recovery journal table name")
        self._client = client
        self._table = table_name
        self._binding = binding
        self._stream_key = f"STREAM#{binding.stream_kind.value}#{binding.stream_id}"
        self._pause_key = f"PAUSE#{binding.stream_kind.value}#{binding.stream_id}"

    @classmethod
    def from_environment(cls) -> AwsDynamoRecoveryJournal:
        try:
            region = os.environ["AWS_REGION"]
            account_id = os.environ["LUCY_AWS_ACCOUNT_ID"]
            table_name = os.environ["LUCY_AWS_RECOVERY_JOURNAL_TABLE"]
            raw_binding = os.environ["LUCY_RECOVERY_STREAM_BINDING_JSON"]
            binding = RecoveryStreamBindingV1.model_validate(json.loads(raw_binding))
        except (KeyError, TypeError, ValueError, ValidationError):
            raise RecoveryJournalError(
                "production recovery journal configuration is incomplete"
            ) from None
        if region != "us-east-1" or re.fullmatch(r"\d{12}", account_id) is None:
            raise RecoveryJournalError("production recovery journal identity is invalid")
        expected_store = f"arn:aws:dynamodb:{region}:{account_id}:table/{table_name}"
        role_prefix = f"arn:aws:iam::{account_id}:role/"
        if (
            binding.independent_store_id != expected_store
            or not binding.writer_identity.startswith(role_prefix)
            or not binding.recovery_identity.startswith(role_prefix)
            or binding.writer_identity == binding.recovery_identity
        ):
            raise RecoveryJournalError("production recovery journal binding is invalid")
        return cls(_aws_client(region), table_name=table_name, binding=binding)

    def head(self) -> RecoveryJournalHeadV1:
        item = self._get({"pk": {"S": self._stream_key}, "sk": {"S": "HEAD"}})
        if item is None:
            raise RecoveryJournalError("independent recovery journal head is unavailable")
        try:
            head = RecoveryJournalHeadV1(
                stream_kind=RecoveryStreamKind(_string(item, "stream_kind")),
                stream_id=UUID(_string(item, "stream_id")),
                authority_epoch=int(_number(item, "authority_epoch")),
                independent_store_id=_string(item, "independent_store_id"),
                binding_manifest_digest=_string(item, "binding_manifest_digest"),
                sequence=int(_number(item, "sequence")),
                event_digest=_string(item, "event_digest"),
            )
            self._require_bound_head(head)
            return head
        except (TypeError, ValueError):
            raise RecoveryJournalError("independent recovery journal head is invalid") from None

    def exact_acknowledgement(
        self, event_id: UUID
    ) -> RecoveryAppendAcknowledgementV1 | None:
        """Read one permanent acknowledgement without exposing event enumeration."""

        acknowledgement = self._read_ack(event_id)
        if acknowledgement is not None:
            self._require_bound_head(acknowledgement.resulting_head)
        return acknowledgement

    def event(self, sequence: int) -> RecoveryJournalEventV1:
        if sequence < 1:
            raise RecoveryJournalError("recovery journal sequence is invalid")
        item = self._get(
            {
                "pk": {"S": self._stream_key},
                "sk": {"S": f"EVENT#{sequence:020d}"},
            }
        )
        if item is None:
            raise RecoveryJournalError("recovery journal event is unavailable")
        try:
            event = RecoveryJournalEventV1.model_validate_json(_string(item, "body"))
        except (TypeError, ValueError):
            raise RecoveryJournalError("recovery journal event is invalid") from None
        self._require_bound_event(event)
        if (
            event.sequence != sequence
            or _string(item, "event_id") != str(event.event_id)
            or _string(item, "event_digest") != event.event_digest
        ):
            raise RecoveryJournalError("recovery journal event metadata differs")
        return event

    def append(
        self,
        event: RecoveryJournalEventV1,
        expected: RecoveryJournalHeadV1,
    ) -> RecoveryAppendAcknowledgementV1:
        self._require_bound_head(expected)
        self._require_bound_event(event)
        resulting = advance_recovery_head(expected, event)
        existing = self._read_ack(event.event_id)
        if existing is not None:
            return self._validate_replay(existing, event)
        acknowledged_at = datetime.now(UTC)
        ack = RecoveryAppendAcknowledgementV1(
            event_id=event.event_id,
            event_digest=event.event_digest,
            resulting_head=resulting,
            acknowledged_at=acknowledged_at,
        )
        values = self._head_values(expected)
        values.update(
            {
                ":next_sequence": {"N": str(resulting.sequence)},
                ":next_digest": {"S": resulting.event_digest},
                ":now_ms": {"N": str(_epoch_ms(acknowledged_at))},
            }
        )
        transaction: list[dict[str, object]] = [
            {
                "Put": {
                    "TableName": self._table,
                    "Item": {
                        "pk": {"S": self._stream_key},
                        "sk": {"S": f"EVENT#{event.sequence:020d}"},
                        "event_id": {"S": str(event.event_id)},
                        "event_digest": {"S": event.event_digest},
                        "body": {"S": event.model_dump_json()},
                    },
                    "ConditionExpression": "attribute_not_exists(pk)",
                }
            },
            {
                "Put": {
                    "TableName": self._table,
                    "Item": {
                        "pk": {"S": f"EVENT#{event.event_id}"},
                        "sk": {"S": "ACK"},
                        "stream_key": {"S": self._stream_key},
                        "event_digest": {"S": event.event_digest},
                        "sequence": {"N": str(event.sequence)},
                        "acknowledged_at": {"S": acknowledged_at.isoformat()},
                    },
                    "ConditionExpression": "attribute_not_exists(pk)",
                }
            },
            {
                "Update": {
                    "TableName": self._table,
                    "Key": {"pk": {"S": self._stream_key}, "sk": {"S": "HEAD"}},
                    "UpdateExpression": "SET #sequence=:next_sequence,event_digest=:next_digest",
                    "ConditionExpression": (
                        "stream_kind=:kind AND stream_id=:stream_id AND "
                        "authority_epoch=:epoch AND independent_store_id=:store AND "
                        "binding_manifest_digest=:manifest AND #sequence=:sequence AND "
                        "event_digest=:digest"
                    ),
                    "ExpressionAttributeNames": {"#sequence": "sequence"},
                    "ExpressionAttributeValues": values,
                }
            },
            {
                    "ConditionCheck": {
                        "TableName": self._table,
                        "Key": {"pk": {"S": self._pause_key}, "sk": {"S": "PAUSE"}},
                    "ConditionExpression": (
                        "attribute_not_exists(pk) OR expires_epoch_ms<=:now_ms"
                    ),
                    "ExpressionAttributeValues": {":now_ms": values[":now_ms"]},
                }
            },
        ]
        try:
            self._client.transact_write_items(
                TransactItems=transaction,
                ClientRequestToken=str(event.event_id),
            )
            return ack
        except (BotoCoreError, ClientError):
            replay = self._read_ack(event.event_id)
            if replay is not None:
                return self._validate_replay(replay, event)
            raise RecoveryJournalError("recovery journal append unconfirmed") from None

    def acquire_pause(
        self,
        *,
        pause_id: UUID,
        recovery_id: UUID,
        expected: RecoveryJournalHeadV1,
        duration: timedelta,
        now: datetime,
    ) -> RecoveryWriterPauseV1:
        self._require_bound_head(expected)
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("pause acquisition time must be timezone-aware")
        if duration <= timedelta(0) or duration > timedelta(seconds=60):
            raise RecoveryJournalError("recovery writer pause duration is invalid")
        existing = self._read_pause()
        if existing is not None and existing.pause_id == pause_id:
            return self._validate_pause_replay(existing, recovery_id, expected)
        generation = 1 if existing is None else existing.fencing_generation + 1
        pause = RecoveryWriterPauseV1(
            pause_id=pause_id,
            recovery_id=recovery_id,
            stream_kind=self._binding.stream_kind,
            stream_id=self._binding.stream_id,
            authority_epoch=self._binding.authority_epoch,
            independent_store_id=self._binding.independent_store_id,
            binding_manifest_digest=self._binding.binding_manifest_digest,
            held_head_sequence=expected.sequence,
            held_head_digest=expected.event_digest,
            fencing_generation=generation,
            acquired_at=now,
            expires_at=now + duration,
        )
        condition = "attribute_not_exists(pk)"
        condition_values: dict[str, dict[str, str]] = {}
        if existing is not None:
            condition = "fencing_generation=:previous AND expires_epoch_ms<=:now_ms"
            condition_values[":previous"] = {"N": str(existing.fencing_generation)}
            condition_values[":now_ms"] = {"N": str(_epoch_ms(now))}
        pause_put: dict[str, object] = {
            "TableName": self._table,
            "Item": {
                "pk": {"S": self._pause_key},
                "sk": {"S": "PAUSE"},
                "pause_id": {"S": str(pause.pause_id)},
                "recovery_id": {"S": str(pause.recovery_id)},
                "fencing_generation": {"N": str(generation)},
                "expires_epoch_ms": {"N": str(_epoch_ms(pause.expires_at))},
                "body": {"S": pause.model_dump_json()},
            },
            "ConditionExpression": condition,
        }
        if condition_values:
            pause_put["ExpressionAttributeValues"] = condition_values
        try:
            self._client.transact_write_items(
                TransactItems=[
                    {"Put": pause_put},
                    {
                        "ConditionCheck": {
                            "TableName": self._table,
                            "Key": {
                                "pk": {"S": self._stream_key},
                                "sk": {"S": "HEAD"},
                            },
                            "ConditionExpression": (
                                "stream_kind=:kind AND stream_id=:stream_id AND "
                                "authority_epoch=:epoch AND independent_store_id=:store AND "
                                "binding_manifest_digest=:manifest AND #sequence=:sequence AND "
                                "event_digest=:digest"
                            ),
                            "ExpressionAttributeNames": {"#sequence": "sequence"},
                            "ExpressionAttributeValues": self._head_values(expected),
                        }
                    },
                ],
                ClientRequestToken=str(pause_id),
            )
            return pause
        except (BotoCoreError, ClientError):
            replay = self._read_pause()
            if replay is not None and replay.pause_id == pause_id:
                return self._validate_pause_replay(replay, recovery_id, expected)
            raise RecoveryJournalError("recovery writer pause acquisition unconfirmed") from None

    def _get(self, key: dict[str, dict[str, str]]) -> dict[str, object] | None:
        try:
            response = self._client.get_item(
                TableName=self._table,
                Key=key,
                ConsistentRead=True,
            )
            item = response.get("Item")
            if item is None:
                return None
            if not isinstance(item, dict):
                raise RecoveryJournalError("independent recovery journal item is invalid")
            return item
        except RecoveryJournalError:
            raise
        except (BotoCoreError, ClientError, TypeError):
            raise RecoveryJournalError("independent recovery journal is unavailable") from None

    def _read_ack(self, event_id: UUID) -> RecoveryAppendAcknowledgementV1 | None:
        item = self._get({"pk": {"S": f"EVENT#{event_id}"}, "sk": {"S": "ACK"}})
        if item is None:
            return None
        try:
            if _string(item, "stream_key") != self._stream_key:
                raise RecoveryJournalError("recovery journal acknowledgement binding differs")
            sequence = int(_number(item, "sequence"))
            digest = _string(item, "event_digest")
            return RecoveryAppendAcknowledgementV1(
                event_id=event_id,
                event_digest=digest,
                resulting_head=RecoveryJournalHeadV1(
                    stream_kind=self._binding.stream_kind,
                    stream_id=self._binding.stream_id,
                    authority_epoch=self._binding.authority_epoch,
                    independent_store_id=self._binding.independent_store_id,
                    binding_manifest_digest=self._binding.binding_manifest_digest,
                    sequence=sequence,
                    event_digest=digest,
                ),
                acknowledged_at=datetime.fromisoformat(_string(item, "acknowledged_at")),
            )
        except (TypeError, ValueError):
            raise RecoveryJournalError("recovery journal acknowledgement is invalid") from None

    def _read_pause(self) -> RecoveryWriterPauseV1 | None:
        item = self._get({"pk": {"S": self._pause_key}, "sk": {"S": "PAUSE"}})
        if item is None:
            return None
        try:
            pause = RecoveryWriterPauseV1.model_validate_json(_string(item, "body"))
        except (TypeError, ValueError):
            raise RecoveryJournalError("recovery writer pause is invalid") from None
        self._require_bound_pause(pause)
        if (
            _string(item, "pause_id") != str(pause.pause_id)
            or _string(item, "recovery_id") != str(pause.recovery_id)
            or int(_number(item, "fencing_generation")) != pause.fencing_generation
            or int(_number(item, "expires_epoch_ms")) != _epoch_ms(pause.expires_at)
        ):
            raise RecoveryJournalError("recovery writer pause metadata differs")
        return pause

    def _validate_replay(
        self,
        acknowledgement: RecoveryAppendAcknowledgementV1,
        event: RecoveryJournalEventV1,
    ) -> RecoveryAppendAcknowledgementV1:
        if (
            acknowledgement.event_digest != event.event_digest
            or acknowledgement.resulting_head.sequence != event.sequence
        ):
            raise RecoveryJournalError("recovery journal event ID conflicts")
        return acknowledgement

    def _validate_pause_replay(
        self,
        pause: RecoveryWriterPauseV1,
        recovery_id: UUID,
        expected: RecoveryJournalHeadV1,
    ) -> RecoveryWriterPauseV1:
        if (
            pause.recovery_id != recovery_id
            or pause.held_head_sequence != expected.sequence
            or pause.held_head_digest != expected.event_digest
        ):
            raise RecoveryJournalError("recovery writer pause ID conflicts")
        return pause

    def _require_bound_head(self, head: RecoveryJournalHeadV1) -> None:
        values = (
            head.stream_kind,
            head.stream_id,
            head.authority_epoch,
            head.independent_store_id,
            head.binding_manifest_digest,
        )
        if values != self._binding_values():
            raise RecoveryJournalError("recovery journal stream binding mismatch")

    def _require_bound_event(self, event: RecoveryJournalEventV1) -> None:
        values = (
            event.stream_kind,
            event.stream_id,
            event.authority_epoch,
            event.independent_store_id,
            event.binding_manifest_digest,
        )
        if values != self._binding_values():
            raise RecoveryJournalError("recovery journal stream binding mismatch")

    def _require_bound_pause(self, pause: RecoveryWriterPauseV1) -> None:
        values = (
            pause.stream_kind,
            pause.stream_id,
            pause.authority_epoch,
            pause.independent_store_id,
            pause.binding_manifest_digest,
        )
        if values != self._binding_values():
            raise RecoveryJournalError("recovery journal stream binding mismatch")

    def _binding_values(self) -> tuple[object, ...]:
        return (
            self._binding.stream_kind,
            self._binding.stream_id,
            self._binding.authority_epoch,
            self._binding.independent_store_id,
            self._binding.binding_manifest_digest,
        )

    def _head_values(self, head: RecoveryJournalHeadV1) -> dict[str, dict[str, str]]:
        return {
            ":kind": {"S": head.stream_kind.value},
            ":stream_id": {"S": str(head.stream_id)},
            ":epoch": {"N": str(head.authority_epoch)},
            ":store": {"S": head.independent_store_id},
            ":manifest": {"S": head.binding_manifest_digest},
            ":sequence": {"N": str(head.sequence)},
            ":digest": {"S": head.event_digest},
        }


def _epoch_ms(value: datetime) -> int:
    return int(value.timestamp() * 1000)


def initialize_recovery_head(
    client: DynamoRecoveryClient,
    *,
    table_name: str,
    binding: RecoveryStreamBindingV1,
) -> bool:
    """Create one immutable genesis head; return False for an exact replay."""

    journal = AwsDynamoRecoveryJournal(client, table_name=table_name, binding=binding)
    stream_key = f"STREAM#{binding.stream_kind.value}#{binding.stream_id}"
    item: dict[str, object] = {
        "pk": {"S": stream_key},
        "sk": {"S": "HEAD"},
        "stream_kind": {"S": binding.stream_kind.value},
        "stream_id": {"S": str(binding.stream_id)},
        "authority_epoch": {"N": str(binding.authority_epoch)},
        "independent_store_id": {"S": binding.independent_store_id},
        "binding_manifest_digest": {"S": binding.binding_manifest_digest},
        "sequence": {"N": "0"},
        "event_digest": {"S": _GENESIS},
    }
    try:
        client.put_item(
            TableName=table_name,
            Item=item,
            ConditionExpression="attribute_not_exists(pk)",
            ReturnValues="NONE",
        )
        return True
    except (BotoCoreError, ClientError):
        expected = RecoveryJournalHeadV1(
            stream_kind=binding.stream_kind,
            stream_id=binding.stream_id,
            authority_epoch=binding.authority_epoch,
            independent_store_id=binding.independent_store_id,
            binding_manifest_digest=binding.binding_manifest_digest,
            sequence=0,
            event_digest=_GENESIS,
        )
        if journal.head() != expected:
            raise RecoveryJournalError("recovery journal genesis conflicts") from None
        return False


def _string(item: dict[str, object], name: str) -> str:
    value = item.get(name)
    if not isinstance(value, dict) or not isinstance(value.get("S"), str):
        raise ValueError("DynamoDB string is invalid")
    result = value["S"]
    assert isinstance(result, str)
    return result


def _number(item: dict[str, object], name: str) -> str:
    value = item.get(name)
    if not isinstance(value, dict) or not isinstance(value.get("N"), str):
        raise ValueError("DynamoDB number is invalid")
    result = value["N"]
    assert isinstance(result, str)
    return result


@lru_cache(maxsize=1)
def _aws_client(region: str) -> DynamoRecoveryClient:
    return cast(DynamoRecoveryClient, boto3.client("dynamodb", region_name=region))
