from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from lucy.archive_crypto import (
    EncryptedPayload,
    EnvelopeCipher,
    MemoryArchiveKeyStore,
    WrappedDataKey,
)
from lucy.memory_extraction import (
    MemoryExtractionDispatchV1,
    MemoryExtractionProviderOutcomeV1,
    memory_extraction_job_id,
)
from lucy.memory_import import ImportManifestRecordV1, ImportManifestV2
from lucy.memory_outcome import (
    EncryptedMemoryOutcomeJournal,
    MemoryOutcomeEnvelopeV1,
    MemoryOutcomeUnavailable,
    WriteOnlyEncryptedMemoryOutcomeJournal,
)

CAMPAIGN = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
SCOPE = UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
RESERVATION = UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
NOW = datetime(2026, 9, 12, tzinfo=UTC)


class Store:
    def __init__(self) -> None:
        self.value: MemoryOutcomeEnvelopeV1 | None = None
        self.load_calls = 0

    def load(self, extraction_job_id: UUID) -> MemoryOutcomeEnvelopeV1 | None:
        self.load_calls += 1
        if self.value is None or self.value.binding.extraction_job_id != extraction_job_id:
            return None
        return self.value

    def put(self, envelope: MemoryOutcomeEnvelopeV1) -> MemoryOutcomeEnvelopeV1:
        if self.value is not None and self.value != envelope:
            raise ValueError("outcome conflict")
        self.value = envelope
        return envelope


class DecryptForbiddenCipher(EnvelopeCipher):
    def decrypt(
        self, evidence_id: UUID, payload: EncryptedPayload, aad: bytes
    ) -> bytes:
        raise AssertionError("write-only outcome path must never decrypt")


class WriteOnlyKeys:
    def __init__(self) -> None:
        self.registry_identity = UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd")
        self.values: dict[UUID, WrappedDataKey] = {}

    def put_new(self, key_ref: UUID, wrapped_key: WrappedDataKey) -> None:
        if key_ref in self.values:
            raise PermissionError("exact-job recovery required")
        self.values[key_ref] = wrapped_key


def test_write_only_outcome_path_never_reads_or_decrypts() -> None:
    store = Store()
    keys = WriteOnlyKeys()
    journal = WriteOnlyEncryptedMemoryOutcomeJournal(
        store,
        cipher=DecryptForbiddenCipher(
            b"k" * 32, b"c" * 32, kek_version="write-only-test-v1"
        ),
        key_writer=keys,
    )

    assert journal.record(
        manifest=_manifest(),
        dispatch=_dispatch(),
        reservation_id=RESERVATION,
        outcome=_outcome(),
    ) == _outcome()
    assert store.load_calls == 0
    assert store.value is not None
    assert set(keys.values) == {store.value.encryption_id}
    assert _outcome().output not in store.value.ciphertext_b64

    with pytest.raises(MemoryOutcomeUnavailable, match="exact-job recovery required"):
        journal.record(
            manifest=_manifest(),
            dispatch=_dispatch(),
            reservation_id=RESERVATION,
            outcome=_outcome(),
        )
    assert store.load_calls == 0


def _manifest() -> ImportManifestV2:
    return ImportManifestV2(
        campaign_id=CAMPAIGN,
        destination_content_scope_id=SCOPE,
        source_namespace="private/test",
        source_conversation_id="pilot",
        parser_version="parser-v1",
        extractor_version="extractor-v1",
        prompt_version="prompt-v1",
        provider_policy_id="private-zdr-v1",
        model_route="openai/test",
        token_accounting_version="canonical-json-byte-upper-bound-v1",
        records=(ImportManifestRecordV1(
            source_record_id="record-1", content_commitment="a" * 64,
            byte_length=10, estimated_tokens=3, source_revision=1,
            role="owner", displayed=True,
        ),),
        max_records=1, max_bytes=10, max_source_estimated_tokens=3,
        max_request_input_tokens=100, max_request_output_tokens=100,
        max_request_total_tokens=200, max_model_spend_microusd=1_000,
        max_attempts=1, expires_at=NOW + timedelta(hours=1),
    )


def _dispatch() -> MemoryExtractionDispatchV1:
    attempt = "pilot:batch:1:attempt:1"
    commitment = "d" * 64
    return MemoryExtractionDispatchV1(
        extraction_job_id=memory_extraction_job_id(
            CAMPAIGN, attempt_key=attempt, request_commitment=commitment
        ),
        attempt_key=attempt, source_record_ids=("record-1",), prompt="synthetic",
        input_tokens=50, output_tokens=50, request_bytes=50,
        request_commitment=commitment, maximum_microusd=1_000, timeout_seconds=30,
    )


def _outcome() -> MemoryExtractionProviderOutcomeV1:
    return MemoryExtractionProviderOutcomeV1(
        output='{"contract_version":"1","candidates":[]}', billed_microusd=400,
        provider_policy_id="private-zdr-v1", model_route="openai/test",
        provider_reference_commitment="e" * 64,
    )


def _journal(store: Store, keys: MemoryArchiveKeyStore) -> EncryptedMemoryOutcomeJournal:
    return EncryptedMemoryOutcomeJournal(
        store,
        cipher=EnvelopeCipher(b"k" * 32, b"c" * 32, kek_version="test-v1"),
        key_store=keys,
    )


def test_outcome_is_encrypted_replayable_and_exact_job_bound() -> None:
    store = Store()
    keys = MemoryArchiveKeyStore()
    journal = _journal(store, keys)

    assert journal.record(
        manifest=_manifest(), dispatch=_dispatch(), reservation_id=RESERVATION,
        outcome=_outcome(),
    ) == _outcome()
    assert store.value is not None
    assert _outcome().output not in store.value.ciphertext_b64
    assert journal.record(
        manifest=_manifest(), dispatch=_dispatch(), reservation_id=RESERVATION,
        outcome=_outcome(),
    ) == _outcome()
    assert journal.load(
        manifest=_manifest(), dispatch=_dispatch(), reservation_id=RESERVATION
    ) == _outcome()
    with pytest.raises(MemoryOutcomeUnavailable, match="replay conflicts"):
        journal.record(
            manifest=_manifest(), dispatch=_dispatch(), reservation_id=RESERVATION,
            outcome=_outcome().model_copy(update={"output": '{"candidates":[]}'}),
        )


def test_missing_key_tamper_and_over_cap_outcome_fail_closed() -> None:
    for mutation in ("missing-key", "ciphertext"):
        store = Store()
        keys = MemoryArchiveKeyStore()
        journal = _journal(store, keys)
        journal.record(
            manifest=_manifest(), dispatch=_dispatch(), reservation_id=RESERVATION,
            outcome=_outcome(),
        )
        assert store.value is not None
        if mutation == "missing-key":
            keys.delete(store.value.encryption_id)
        else:
            store.value = store.value.model_copy(update={"ciphertext_b64": "AAAA"})
        with pytest.raises(MemoryOutcomeUnavailable):
            journal.load(
                manifest=_manifest(), dispatch=_dispatch(), reservation_id=RESERVATION
            )

    with pytest.raises(MemoryOutcomeUnavailable, match="exceeds"):
        _journal(Store(), MemoryArchiveKeyStore()).record(
            manifest=_manifest(), dispatch=_dispatch(), reservation_id=RESERVATION,
            outcome=_outcome().model_copy(update={"billed_microusd": 1_001}),
        )
