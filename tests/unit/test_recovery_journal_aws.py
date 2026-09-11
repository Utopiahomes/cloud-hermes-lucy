from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any, NoReturn
from uuid import uuid4

import pytest
from botocore.exceptions import ClientError, EndpointConnectionError  # type: ignore[import-untyped]

import lucy.recovery_journal_aws as aws_module
from lucy.recovery_journal import (
    AuthorityJournalEffectV1,
    RecoveryJournalError,
    RecoveryJournalEventV1,
    RecoveryJournalHeadV1,
    RecoveryStreamBindingV1,
    RecoveryStreamKind,
    recovery_event_digest,
)
from lucy.recovery_journal_aws import AwsDynamoRecoveryJournal, initialize_recovery_head


class FakeDynamo:
    def __init__(self, bound: RecoveryStreamBindingV1) -> None:
        stream_key = f"STREAM#{bound.stream_kind.value}#{bound.stream_id}"
        self.items: dict[tuple[str, str], dict[str, object]] = {
            (stream_key, "HEAD"): {
                "pk": {"S": stream_key},
                "sk": {"S": "HEAD"},
                "stream_kind": {"S": bound.stream_kind.value},
                "stream_id": {"S": str(bound.stream_id)},
                "authority_epoch": {"N": str(bound.authority_epoch)},
                "independent_store_id": {"S": bound.independent_store_id},
                "binding_manifest_digest": {"S": bound.binding_manifest_digest},
                "sequence": {"N": "0"},
                "event_digest": {"S": "0" * 64},
            }
        }
        self.transactions: list[list[dict[str, object]]] = []
        self.raise_after_commit = False

    def put_item(self, **kwargs: object) -> dict[str, object]:
        item = kwargs["Item"]
        assert isinstance(item, dict)
        key = _key(item)
        if key in self.items:
            raise ClientError(
                {
                    "Error": {
                        "Code": "ConditionalCheckFailedException",
                        "Message": "conditional",
                    }
                },
                "PutItem",
            )
        self.items[key] = item
        return {}

    def get_item(self, **kwargs: object) -> dict[str, object]:
        assert kwargs["ConsistentRead"] is True
        key = _key(kwargs["Key"])
        item = self.items.get(key)
        return {} if item is None else {"Item": item}

    def transact_write_items(self, **kwargs: object) -> dict[str, object]:
        actions = kwargs["TransactItems"]
        assert isinstance(actions, list)
        typed = actions
        self._validate(typed)
        self._apply(typed)
        self.transactions.append(typed)
        if self.raise_after_commit:
            self.raise_after_commit = False
            raise EndpointConnectionError(endpoint_url="https://synthetic.invalid")
        return {}

    def _validate(self, actions: list[dict[str, object]]) -> None:
        for action in actions:
            if "Put" in action:
                put = action["Put"]
                assert isinstance(put, dict)
                item = put["Item"]
                assert isinstance(item, dict)
                key = _key(item)
                condition = put.get("ConditionExpression")
                existing = self.items.get(key)
                if condition == "attribute_not_exists(pk)" and existing is not None:
                    _cancel()
                if isinstance(condition, str) and condition.startswith("fencing_generation"):
                    values = put["ExpressionAttributeValues"]
                    assert isinstance(values, dict)
                    if existing is None or _n(existing, "fencing_generation") != _n(
                        values, ":previous"
                    ):
                        _cancel()
                    if _n(existing, "expires_epoch_ms") > _n(values, ":now_ms"):
                        _cancel()
            elif "Update" in action:
                update = action["Update"]
                assert isinstance(update, dict)
                current = self.items.get(_key(update["Key"]))
                values = update["ExpressionAttributeValues"]
                assert isinstance(values, dict)
                if current is None or not _head_matches(current, values):
                    _cancel()
            else:
                check = action["ConditionCheck"]
                assert isinstance(check, dict)
                current = self.items.get(_key(check["Key"]))
                condition = check["ConditionExpression"]
                values = check["ExpressionAttributeValues"]
                assert isinstance(values, dict)
                if condition == "attribute_not_exists(pk) OR expires_epoch_ms<=:now_ms":
                    if current is not None and _n(current, "expires_epoch_ms") > _n(
                        values, ":now_ms"
                    ):
                        _cancel()
                elif current is None or not _head_matches(current, values):
                    _cancel()

    def _apply(self, actions: list[dict[str, object]]) -> None:
        for action in actions:
            if "Put" in action:
                put = action["Put"]
                assert isinstance(put, dict) and isinstance(put["Item"], dict)
                self.items[_key(put["Item"])] = put["Item"]
            elif "Update" in action:
                update = action["Update"]
                assert isinstance(update, dict)
                current = self.items[_key(update["Key"])]
                values = update["ExpressionAttributeValues"]
                assert isinstance(values, dict)
                current["sequence"] = values[":next_sequence"]
                current["event_digest"] = values[":next_digest"]


def _binding() -> RecoveryStreamBindingV1:
    return RecoveryStreamBindingV1(
        stream_kind=RecoveryStreamKind.AUTHORITY,
        stream_id=uuid4(),
        authority_epoch=1,
        independent_store_id="arn:aws:dynamodb:us-east-1:429870640638:table/synthetic",
        writer_identity="arn:aws:iam::429870640638:role/synthetic-writer",
        recovery_identity="arn:aws:iam::429870640638:role/synthetic-recovery",
        binding_manifest_digest="a" * 64,
    )


def _event(
    bound: RecoveryStreamBindingV1, before: RecoveryJournalHeadV1
) -> RecoveryJournalEventV1:
    values: dict[str, Any] = {
        "event_id": uuid4(),
        "stream_kind": bound.stream_kind,
        "stream_id": bound.stream_id,
        "authority_epoch": bound.authority_epoch,
        "independent_store_id": bound.independent_store_id,
        "binding_manifest_digest": bound.binding_manifest_digest,
        "sequence": before.sequence + 1,
        "previous_digest": before.event_digest,
        "operation_id": uuid4(),
        "idempotency_key": f"authority:{uuid4()}",
        "source_authority_ref": "synthetic-owner-proof",
        "source_authority_digest": "b" * 64,
        "source_generation": 1,
        "occurred_at": datetime.now(UTC),
        "effect": AuthorityJournalEffectV1(
            transition="membership_revoked",
            security_realm_id=uuid4(),
            workspace_id=uuid4(),
            subject_id=uuid4(),
            previous_generation=1,
            new_generation=2,
            previous_state="active",
            new_state="revoked",
        ),
        "event_digest": "0" * 64,
    }
    unsigned = RecoveryJournalEventV1.model_construct(**values)
    values["event_digest"] = recovery_event_digest(unsigned)
    return RecoveryJournalEventV1.model_validate(values)


def _journal() -> tuple[
    RecoveryStreamBindingV1, FakeDynamo, AwsDynamoRecoveryJournal
]:
    bound = _binding()
    client = FakeDynamo(bound)
    return bound, client, AwsDynamoRecoveryJournal(
        client, table_name="lucy-synthetic-recovery", binding=bound
    )


def test_append_is_one_conditional_transaction_and_reads_are_consistent() -> None:
    bound, client, journal = _journal()
    before = journal.head()
    change = _event(bound, before)
    acknowledgement = journal.append(change, before)
    assert acknowledgement.resulting_head == journal.head()
    assert journal.exact_acknowledgement(change.event_id) == acknowledgement
    assert journal.exact_acknowledgement(uuid4()) is None
    assert journal.event(1) == change
    assert len(client.transactions[0]) == 4
    assert {next(iter(action)) for action in client.transactions[0]} == {
        "Put",
        "Update",
        "ConditionCheck",
    }


def test_response_loss_recovers_exact_ack_and_conflicting_id_fails() -> None:
    bound, client, journal = _journal()
    before = journal.head()
    change = _event(bound, before)
    client.raise_after_commit = True
    acknowledgement = journal.append(change, before)
    assert acknowledgement.event_id == change.event_id
    assert journal.append(change, before).resulting_head == acknowledgement.resulting_head
    conflicting = change.model_copy(update={"event_digest": "f" * 64})
    with pytest.raises(RecoveryJournalError, match="ID conflicts"):
        journal.append(conflicting, before)


def test_event_metadata_substitution_is_rejected() -> None:
    bound, client, journal = _journal()
    before = journal.head()
    change = _event(bound, before)
    journal.append(change, before)
    stream_key = f"STREAM#{bound.stream_kind.value}#{bound.stream_id}"
    client.items[(stream_key, "EVENT#00000000000000000001")]["event_id"] = {
        "S": str(uuid4())
    }
    with pytest.raises(RecoveryJournalError, match="metadata differs"):
        journal.event(1)


def test_stale_head_and_active_pause_fail_closed(
    caplog: pytest.LogCaptureFixture,
) -> None:
    bound, client, journal = _journal()
    before = journal.head()
    journal.append(_event(bound, before), before)
    with pytest.raises(RecoveryJournalError, match="unconfirmed"):
        journal.append(_event(bound, before), before)
    assert "code=TransactionCanceledException" in caplog.text
    assert "conditional" not in caplog.text

    current = journal.head()
    pause_id = uuid4()
    recovery_id = uuid4()
    held = journal.acquire_pause(
        pause_id=pause_id,
        recovery_id=recovery_id,
        expected=current,
        duration=timedelta(seconds=30),
        now=datetime.now(UTC),
    )
    pause_put = client.transactions[1][0]["Put"]
    assert isinstance(pause_put, dict)
    pause_item = pause_put["Item"]
    assert isinstance(pause_item, dict)
    assert _s(pause_item, "pk") == f"PAUSE#{bound.stream_kind.value}#{bound.stream_id}"
    assert "ExpressionAttributeValues" not in pause_put
    assert journal.acquire_pause(
        pause_id=pause_id,
        recovery_id=recovery_id,
        expected=current,
        duration=timedelta(seconds=30),
        now=held.acquired_at,
    ) == held
    with pytest.raises(RecoveryJournalError, match="unconfirmed"):
        journal.append(_event(bound, current), current)


def test_environment_factory_pins_account_region_table_and_distinct_roles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bound = _binding()
    sentinel = FakeDynamo(bound)
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("LUCY_AWS_ACCOUNT_ID", "429870640638")
    monkeypatch.setenv("LUCY_AWS_RECOVERY_JOURNAL_TABLE", "synthetic")
    monkeypatch.setenv("LUCY_RECOVERY_STREAM_BINDING_JSON", bound.model_dump_json())
    monkeypatch.setattr(aws_module, "_aws_client", lambda _: sentinel)
    journal = AwsDynamoRecoveryJournal.from_environment()
    assert journal.head().sequence == 0

    values = bound.model_dump(mode="json")
    values["recovery_identity"] = values["writer_identity"]
    monkeypatch.setenv("LUCY_RECOVERY_STREAM_BINDING_JSON", json.dumps(values))
    with pytest.raises(RecoveryJournalError, match="binding is invalid"):
        AwsDynamoRecoveryJournal.from_environment()


def test_environment_factory_rejects_missing_or_cross_account_store(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(RecoveryJournalError, match="configuration is incomplete"):
        AwsDynamoRecoveryJournal.from_environment()

    bound = _binding().model_dump(mode="json")
    bound["independent_store_id"] = (
        "arn:aws:dynamodb:us-east-1:000000000000:table/synthetic"
    )
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("LUCY_AWS_ACCOUNT_ID", "429870640638")
    monkeypatch.setenv("LUCY_AWS_RECOVERY_JOURNAL_TABLE", "synthetic")
    monkeypatch.setenv("LUCY_RECOVERY_STREAM_BINDING_JSON", json.dumps(bound))
    with pytest.raises(RecoveryJournalError, match="binding is invalid"):
        AwsDynamoRecoveryJournal.from_environment()


def test_genesis_initializer_is_create_only_and_exactly_replayable() -> None:
    bound = _binding()
    client = FakeDynamo(bound)
    client.items.clear()
    assert initialize_recovery_head(
        client, table_name="lucy-synthetic-recovery", binding=bound
    )
    assert not initialize_recovery_head(
        client, table_name="lucy-synthetic-recovery", binding=bound
    )
    stream_key = f"STREAM#{bound.stream_kind.value}#{bound.stream_id}"
    client.items[(stream_key, "HEAD")]["binding_manifest_digest"] = {"S": "f" * 64}
    with pytest.raises(RecoveryJournalError, match="stream binding mismatch"):
        initialize_recovery_head(
            client, table_name="lucy-synthetic-recovery", binding=bound
        )


def _key(value: object) -> tuple[str, str]:
    assert isinstance(value, dict)
    return _s(value, "pk"), _s(value, "sk")


def _s(value: dict[str, object], name: str) -> str:
    attribute = value[name]
    assert isinstance(attribute, dict) and isinstance(attribute["S"], str)
    return attribute["S"]


def _n(value: dict[str, object], name: str) -> int:
    attribute = value[name]
    assert isinstance(attribute, dict) and isinstance(attribute["N"], str)
    return int(attribute["N"])


def _head_matches(current: dict[str, object], values: dict[str, object]) -> bool:
    return (
        _s(current, "stream_kind") == _s(values, ":kind")
        and _s(current, "stream_id") == _s(values, ":stream_id")
        and _n(current, "authority_epoch") == _n(values, ":epoch")
        and _s(current, "independent_store_id") == _s(values, ":store")
        and _s(current, "binding_manifest_digest") == _s(values, ":manifest")
        and _n(current, "sequence") == _n(values, ":sequence")
        and _s(current, "event_digest") == _s(values, ":digest")
    )


def _cancel() -> NoReturn:
    raise ClientError(
        {"Error": {"Code": "TransactionCanceledException", "Message": "conditional"}},
        "TransactWriteItems",
    )
