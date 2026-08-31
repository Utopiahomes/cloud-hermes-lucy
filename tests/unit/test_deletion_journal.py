from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from botocore.exceptions import ClientError, EndpointConnectionError
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

import lucy.deletion_journal as journal_module
from lucy.authorization import SensitiveActionPermitSigner, SensitiveActionPermitV1
from lucy.deletion_journal import (
    AwsDynamoDeletionJournal,
    DeletionIntentV1,
    DeletionJournal,
    DeletionJournalError,
    DeletionTargetV1,
    SqliteDeletionJournal,
    deletion_journal_from_environment,
)


def intent(journal: DeletionJournal) -> DeletionIntentV1:
    head = journal.head()
    evidence_id = uuid4()
    now = datetime.now(UTC)
    permit = SensitiveActionPermitSigner(Ed25519PrivateKey.generate()).sign(
        SensitiveActionPermitV1(
            permit_id=uuid4(),
            action="evidence.delete",
            owner_subject="synthetic-owner",
            owner_interaction_id="synthetic-event",
            evidence_ids=(evidence_id,),
            reason="owner_request",
            max_records=1,
            max_bytes=1,
            issued_at=now,
            expires_at=now + timedelta(seconds=30),
            nonce="n" * 32,
            signature="",
        )
    )
    return DeletionIntentV1(
        intent_id=uuid4(),
        journal_id=head.journal_id,
        registry_id=head.registry_id,
        operation_id=uuid4(),
        idempotency_key=str(uuid4()),
        evidence_id=evidence_id,
        reason="owner_request",
        accepted_at=now,
        permit=permit,
        targets=(DeletionTargetV1(evidence_id=evidence_id, key_ref=uuid4()),),
    )


def test_append_survives_fresh_provider_and_rejects_stale_head(tmp_path: Path) -> None:
    path = tmp_path / "journal.sqlite"
    journal = SqliteDeletionJournal.initialize(path, registry_id=uuid4())
    before = journal.head()
    entry = journal.append(intent(journal), before)
    fresh = SqliteDeletionJournal(
        path, journal_id=before.journal_id, registry_id=before.registry_id
    )
    assert fresh.head().sequence == 1
    assert fresh.entry(1) == entry
    with pytest.raises(DeletionJournalError, match="advanced"):
        journal.append(intent(journal), before)
    assert fresh.head().sequence == 1


@pytest.mark.parametrize("field", ["journal_id", "registry_id"])
def test_wrong_identity_is_not_an_empty_journal(tmp_path: Path, field: str) -> None:
    path = tmp_path / "journal.sqlite"
    journal = SqliteDeletionJournal.initialize(path, registry_id=uuid4())
    identity = journal.head().model_dump(include={"journal_id", "registry_id"})
    identity[field] = uuid4()
    with pytest.raises(DeletionJournalError, match="identity"):
        SqliteDeletionJournal(path, **identity).head()


def test_missing_journal_does_not_recreate_itself(tmp_path: Path) -> None:
    path = tmp_path / "absent.sqlite"
    journal = SqliteDeletionJournal(path, journal_id=uuid4(), registry_id=uuid4())
    with pytest.raises(DeletionJournalError, match="unavailable"):
        journal.head()
    assert not path.exists()


def test_initialize_never_overwrites_existing_store(tmp_path: Path) -> None:
    path = tmp_path / "journal.sqlite"
    journal = SqliteDeletionJournal.initialize(path, registry_id=uuid4())
    journal.append(intent(journal), journal.head())
    with pytest.raises(FileExistsError):
        SqliteDeletionJournal.initialize(path, registry_id=uuid4())
    assert journal.head().sequence == 1


@pytest.mark.parametrize(
    "sql",
    [
        "DELETE FROM intents",
        "UPDATE intents SET body='{}'",
        "DELETE FROM identity",
        "UPDATE identity SET registry_id='forged'",
    ],
)
def test_store_rejects_mutating_history(tmp_path: Path, sql: str) -> None:
    path = tmp_path / "journal.sqlite"
    journal = SqliteDeletionJournal.initialize(path, registry_id=uuid4())
    journal.append(intent(journal), journal.head())
    with sqlite3.connect(path) as connection, pytest.raises(sqlite3.IntegrityError):
        connection.execute(sql)


def test_corrupt_manifest_fails_integrity_validation(tmp_path: Path) -> None:
    path = tmp_path / "journal.sqlite"
    journal = SqliteDeletionJournal.initialize(path, registry_id=uuid4())
    journal.append(intent(journal), journal.head())
    # The acceptance provider trusts filesystem writers. Simulate accidental
    # corruption explicitly, not a claim that a hash chain stops a hostile owner.
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TRIGGER intents_no_update")
        connection.execute("UPDATE intents SET body='{}'")
    with pytest.raises(DeletionJournalError, match="corrupt"):
        journal.entry(1)


@pytest.mark.parametrize("change", ["expired", "root", "duplicate", "unsigned_scope"])
def test_intent_contract_cannot_expand_or_backdate_authority(tmp_path: Path, change: str) -> None:
    journal = SqliteDeletionJournal.initialize(tmp_path / "journal.sqlite", registry_id=uuid4())
    candidate = intent(journal).model_dump()
    if change == "expired":
        candidate["accepted_at"] = candidate["permit"]["expires_at"]
    elif change == "root":
        candidate["evidence_id"] = uuid4()
    elif change == "duplicate":
        candidate["targets"] = candidate["targets"] * 2
    else:
        candidate["reason"] = "sensitive_data"
    with pytest.raises(ValidationError):
        DeletionIntentV1.model_validate(candidate)


def test_production_cannot_fall_back_to_a_local_journal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LUCY_ENVIRONMENT", "production")
    with pytest.raises(DeletionJournalError, match="production"):
        deletion_journal_from_environment()


def test_cloud_journal_environment_binds_region_tables_and_identities(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    journal_id, registry_id = uuid4(), uuid4()
    sentinel = object()
    calls: list[tuple[str, str, str, UUID, UUID]] = []
    monkeypatch.setenv("LUCY_ARCHIVE_BACKEND", "aws-kms-dynamodb")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("LUCY_AWS_DELETION_HEAD_TABLE", "lucy-deletion-journal-head")
    monkeypatch.setenv("LUCY_AWS_DELETION_INTENT_TABLE", "lucy-deletion-journal-intents")
    monkeypatch.setenv("LUCY_DELETION_JOURNAL_ID", str(journal_id))
    monkeypatch.setenv("LUCY_ARCHIVE_REGISTRY_ID", str(registry_id))

    def provider(
        region: str,
        head_table: str,
        intent_table: str,
        configured_journal_id: UUID,
        configured_registry_id: UUID,
    ) -> object:
        calls.append(
            (
                region,
                head_table,
                intent_table,
                configured_journal_id,
                configured_registry_id,
            )
        )
        return sentinel

    monkeypatch.setattr(journal_module, "_aws_journal", provider)
    assert deletion_journal_from_environment() is sentinel
    assert calls == [
        (
            "us-east-1",
            "lucy-deletion-journal-head",
            "lucy-deletion-journal-intents",
            journal_id,
            registry_id,
        )
    ]


class FakeCloudJournalClient:
    def __init__(self, journal_id: UUID, registry_id: UUID) -> None:
        self.head_item: dict[str, Any] = {
            "journal_id": {"S": str(journal_id)},
            "registry_id": {"S": str(registry_id)},
            "sequence": {"N": "0"},
            "digest": {"S": "0" * 64},
        }
        self.intents: dict[tuple[str, str], dict[str, Any]] = {}
        self.get_calls: list[dict[str, Any]] = []
        self.transaction_calls: list[dict[str, Any]] = []
        self.failure: str | None = None

    def get_item(self, **kwargs: Any) -> dict[str, Any]:
        self.get_calls.append(kwargs)
        key = kwargs["Key"]
        if "journal_key" in key:
            return {"Item": self.head_item.copy()}
        item = self.intents.get((key["journal_id"]["S"], key["entry_key"]["S"]))
        return {} if item is None else {"Item": item.copy()}

    def transact_write_items(self, **kwargs: Any) -> dict[str, Any]:
        self.transaction_calls.append(kwargs)
        if self.failure == "before":
            raise EndpointConnectionError(endpoint_url="https://dynamodb.invalid")
        update = kwargs["TransactItems"][0]["Update"]
        values = update["ExpressionAttributeValues"]
        if (
            self.head_item["sequence"] != values[":expected"]
            or self.head_item["digest"] != values[":digest"]
        ):
            raise ClientError(
                {"Error": {"Code": "TransactionCanceledException"}},
                "TransactWriteItems",
            )
        for action in kwargs["TransactItems"][1:]:
            item = action["Put"]["Item"]
            key = (item["journal_id"]["S"], item["entry_key"]["S"])
            if key in self.intents:
                raise AssertionError("conditional put collision")
            self.intents[key] = item.copy()
        self.head_item.update(
            sequence=values[":next"],
            digest=values[":next_digest"],
            intent_id=values[":intent"],
        )
        if self.failure == "after":
            raise EndpointConnectionError(endpoint_url="https://dynamodb.invalid")
        return {}


def cloud_journal() -> tuple[FakeCloudJournalClient, AwsDynamoDeletionJournal]:
    journal_id, registry_id = uuid4(), uuid4()
    client = FakeCloudJournalClient(journal_id, registry_id)
    journal = AwsDynamoDeletionJournal(
        client,
        head_table="synthetic-head",
        intent_table="synthetic-intents",
        journal_id=journal_id,
        registry_id=registry_id,
    )
    return client, journal


def test_cloud_append_is_atomic_chunked_and_strongly_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, journal = cloud_journal()
    monkeypatch.setattr(journal_module, "DYNAMO_CHUNK_BYTES", 200)
    before = journal.head()
    accepted = intent(journal)
    entry = journal.append(accepted, before)
    assert journal.head().sequence == 1
    assert journal.entry(1) == entry
    transaction = client.transaction_calls[0]
    assert transaction["ClientRequestToken"] == str(accepted.intent_id)
    assert len(transaction["TransactItems"]) > 3  # head + metadata + several chunks
    assert all(call["ConsistentRead"] is True for call in client.get_calls)
    head_reads = [call for call in client.get_calls if "journal_key" in call["Key"]]
    assert all("ProjectionExpression" in call for call in head_reads)


@pytest.mark.parametrize("failure", ["before", "after"])
def test_cloud_append_distinguishes_failure_from_committed_lost_response(failure: str) -> None:
    client, journal = cloud_journal()
    accepted = intent(journal)
    client.failure = failure
    if failure == "before":
        with pytest.raises(DeletionJournalError, match="unconfirmed"):
            journal.append(accepted, journal.head())
        assert journal.head().sequence == 0
    else:
        result = journal.append(accepted, journal.head())
        assert result.intent == accepted
        assert journal.head().sequence == 1


def test_cloud_entry_missing_chunk_or_wrong_identity_fails_closed() -> None:
    client, journal = cloud_journal()
    accepted = intent(journal)
    journal.append(accepted, journal.head())
    chunk_key = next(key for key in client.intents if not key[1].endswith("#meta"))
    del client.intents[chunk_key]
    with pytest.raises(DeletionJournalError, match="incomplete"):
        journal.entry(1)
    client.head_item["registry_id"] = {"S": str(uuid4())}
    with pytest.raises(DeletionJournalError, match="identity"):
        journal.head()


def test_cloud_journal_rejects_oversize_without_partial_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, journal = cloud_journal()
    monkeypatch.setattr(journal_module, "DYNAMO_CHUNK_BYTES", 1)
    with pytest.raises(DeletionJournalError, match="limit"):
        journal.append(intent(journal), journal.head())
    assert client.transaction_calls == []
    assert journal.head().sequence == 0


@pytest.mark.parametrize(
    ("head", "intents"),
    [("x", "valid-intents"), ("valid-head", "x"), ("same-table", "same-table")],
)
def test_cloud_journal_requires_distinct_valid_table_names(head: str, intents: str) -> None:
    with pytest.raises(ValueError):
        AwsDynamoDeletionJournal(
            FakeCloudJournalClient(uuid4(), uuid4()),
            head_table=head,
            intent_table=intents,
            journal_id=uuid4(),
            registry_id=uuid4(),
        )
