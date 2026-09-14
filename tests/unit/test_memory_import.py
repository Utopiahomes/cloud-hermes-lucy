import base64
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from lucy.contracts.security_v1_3 import OriginScopeV1
from lucy.memory_import import (
    AssertionStatus,
    ContextBudgetV1,
    ContextItemV1,
    EpistemicStatus,
    ImportManifestRecordV1,
    ImportManifestV1,
    ImportManifestV2,
    MemoryCandidatePayloadV1,
    MemoryKind,
    ProtectionClass,
    SourceSpanV1,
    SyntheticConversationV1,
    SyntheticMessageV1,
    build_archive_requests,
    build_synthetic_manifest,
    compile_context,
    load_synthetic_conversation,
    verify_synthetic_manifest,
)
from lucy.realm_archive import (
    GeneratedDataKeyV1,
    RealmArchiveEncryptor,
    RealmArchiveEnvelopeV1,
    RealmArchiveIdentityV1,
)

SCOPE = UUID("00000000-0000-4000-8000-000000000001")
EVIDENCE = UUID("00000000-0000-4000-8000-000000000002")
CANDIDATE = UUID("00000000-0000-4000-8000-000000000003")
CLAIM = UUID("00000000-0000-4000-8000-000000000004")
NOW = datetime(2026, 9, 12, 12, 0, tzinfo=UTC)
KEY_ARN = (
    "arn:aws:kms:us-east-1:123456789012:"
    "key/11111111-1111-4111-8111-111111111111"
)


class _ArchiveBackend:
    def __init__(self) -> None:
        self.envelopes: dict[UUID, RealmArchiveEnvelopeV1] = {}
        self.contexts: list[dict[str, str]] = []

    def generate_data_key(
        self, *, key_arn: str, encryption_context: dict[str, str]
    ) -> GeneratedDataKeyV1:
        self.contexts.append(encryption_context)
        return GeneratedDataKeyV1(b"d" * 32, b"wrapped", key_arn, "synthetic-kms")

    def load_archive_envelope(self, key_ref: UUID) -> RealmArchiveEnvelopeV1 | None:
        return self.envelopes.get(key_ref)

    def put_archive_envelope(
        self,
        *,
        envelope: RealmArchiveEnvelopeV1,
        wrapped_key: bytes,
        key_arn: str,
    ) -> None:
        assert wrapped_key == b"wrapped"
        assert key_arn == KEY_ARN
        self.envelopes[envelope.wrapper_binding.wrapped_key_ref] = envelope


def _candidate() -> MemoryCandidatePayloadV1:
    return MemoryCandidatePayloadV1(
        candidate_id=CANDIDATE,
        candidate_version=1,
        campaign_id=UUID("00000000-0000-4000-8000-000000000006"),
        manifest_digest="b" * 64,
        extraction_job_id=UUID("00000000-0000-4000-8000-000000000007"),
        extractor_version="synthetic-extractor-v1",
        prompt_version="synthetic-prompt-v1",
        model_route="none",
        destination_content_scope_id=SCOPE,
        subject="Ray",
        predicate="selected_architecture",
        object="Use the revised memory plan",
        confidence_millionths=1_000_000,
        memory_kind=MemoryKind.ASSERTION,
        assertion_status=AssertionStatus.DECISION,
        epistemic_status=EpistemicStatus.CURRENT,
        domain_tags=("cloud-lucy", "engineering"),
        event_time=NOW,
        valid_from=NOW,
        sources=(
            SourceSpanV1(
                source_record_id="synthetic:message-1",
                evidence_id=EVIDENCE,
                record_version=1,
                byte_start=0,
                byte_end=34,
            ),
        ),
    )


def test_candidate_digest_binds_content_source_scope_and_classification() -> None:
    original = _candidate()
    assert original.digest == _candidate().digest
    changed = (
        original.model_copy(update={"protection_class": ProtectionClass.ORDINARY_PRIVATE})
    )
    assert changed.digest != original.digest
    changed_source = original.model_copy(
        update={
            "sources": (
                original.sources[0].model_copy(update={"byte_end": 33}),
            )
        }
    )
    assert changed_source.digest != original.digest


def test_candidate_rejects_duplicate_or_invalid_source_spans() -> None:
    source = _candidate().sources[0]
    with pytest.raises(ValueError, match="unique"):
        _candidate().model_copy(update={"sources": (source, source)}).model_validate(
            _candidate().model_copy(update={"sources": (source, source)}).model_dump()
        )
    with pytest.raises(ValueError, match="greater"):
        SourceSpanV1(
            source_record_id="synthetic:message-1",
            evidence_id=EVIDENCE,
            record_version=1,
            byte_start=4,
            byte_end=4,
        )


def test_synthetic_conversation_preserves_alternate_branches() -> None:
    conversation = SyntheticConversationV1(
        conversation_id="synthetic-1",
        title="Decision and reversal",
        messages=(
            SyntheticMessageV1(
                message_id="root", role="owner", occurred_at=NOW, content="Pick A"
            ),
            SyntheticMessageV1(
                message_id="shown",
                parent_message_id="root",
                role="assistant",
                occurred_at=NOW,
                content="I recommend A",
            ),
            SyntheticMessageV1(
                message_id="alternate",
                parent_message_id="root",
                role="assistant",
                occurred_at=NOW,
                content="I recommend B",
                displayed=False,
            ),
        ),
    )
    assert [item.message_id for item in conversation.messages if not item.displayed] == [
        "alternate"
    ]


def test_manifest_digest_and_campaign_cap_include_retry_policy() -> None:
    manifest = ImportManifestV1(
        campaign_id=CANDIDATE,
        destination_content_scope_id=SCOPE,
        source_namespace="raymond-private/chatgpt-export",
        source_conversation_id="synthetic-1",
        parser_version="synthetic-v1",
        extractor_version="extractor-v1",
        prompt_version="prompt-v1",
        provider_policy_id="local-only",
        model_route="none",
        records=(
            ImportManifestRecordV1(
                source_record_id="synthetic-1:root",
                content_commitment="a" * 64,
                byte_length=6,
                estimated_tokens=2,
                source_revision=1,
                role="owner",
                displayed=True,
            ),
        ),
        max_records=1,
        max_bytes=6,
        max_input_tokens=2,
        max_model_spend_microusd=50_000,
        max_attempts=3,
        expires_at=datetime(2026, 9, 13, tzinfo=UTC),
    )
    assert manifest.digest != manifest.model_copy(update={"max_attempts": 4}).digest
    assert manifest.digest != manifest.model_copy(update={"max_model_spend_microusd": 1}).digest


def test_v1_manifest_round_trip_preserves_historical_digest() -> None:
    manifest = ImportManifestV1(
        campaign_id=CANDIDATE,
        destination_content_scope_id=SCOPE,
        source_namespace="raymond-private/chatgpt-export",
        source_conversation_id="synthetic-1",
        parser_version="synthetic-v1",
        extractor_version="extractor-v1",
        prompt_version="prompt-v1",
        provider_policy_id="local-only",
        model_route="none",
        records=(
            ImportManifestRecordV1(
                source_record_id="synthetic-1:root",
                content_commitment="a" * 64,
                byte_length=6,
                estimated_tokens=2,
                source_revision=1,
                role="owner",
                displayed=True,
            ),
        ),
        max_records=1,
        max_bytes=6,
        max_input_tokens=2,
        max_model_spend_microusd=50_000,
        max_attempts=3,
        expires_at=datetime(2026, 9, 13, tzinfo=UTC),
    )

    restored = ImportManifestV1.model_validate_json(manifest.model_dump_json())

    assert restored == manifest
    assert restored.digest == manifest.digest


def test_v2_manifest_binds_separate_source_and_complete_request_budgets() -> None:
    values = {
        "campaign_id": CANDIDATE,
        "destination_content_scope_id": SCOPE,
        "source_namespace": "raymond-private/chatgpt-export",
        "source_conversation_id": "pilot:selection",
        "parser_version": "parser-v1",
        "extractor_version": "extractor-v1",
        "prompt_version": "prompt-v1",
        "provider_policy_id": "private-zdr-v1",
        "model_route": "openai/gpt-oss-20b",
        "token_accounting_version": "openrouter-conservative-v1",
        "records": (
            ImportManifestRecordV1(
                source_record_id="conversation:node:message",
                content_commitment="a" * 64,
                byte_length=17,
                estimated_tokens=6,
                source_revision=1,
                role="owner",
                displayed=True,
            ),
        ),
        "max_records": 1,
        "max_bytes": 17,
        "max_source_estimated_tokens": 6,
        "max_request_input_tokens": 100,
        "max_request_output_tokens": 50,
        "max_request_total_tokens": 150,
        "max_model_spend_microusd": 10_000,
        "max_attempts": 3,
        "expires_at": datetime(2026, 9, 13, tzinfo=UTC),
    }
    manifest = ImportManifestV2.model_validate(values)

    assert ImportManifestV2.model_validate_json(manifest.model_dump_json()) == manifest
    for field, changed in (
        ("max_source_estimated_tokens", 7),
        ("max_request_input_tokens", 101),
        ("max_request_output_tokens", 51),
        ("max_request_total_tokens", 151),
        ("token_accounting_version", "openrouter-conservative-v2"),
    ):
        assert manifest.model_copy(update={field: changed}).digest != manifest.digest

    with pytest.raises(ValueError, match="source-token limit"):
        ImportManifestV2.model_validate({**values, "max_source_estimated_tokens": 5})
    with pytest.raises(ValueError, match="total ceiling"):
        ImportManifestV2.model_validate({**values, "max_request_total_tokens": 149})


def test_synthetic_fixture_builds_exact_protected_archive_requests() -> None:
    fixture = Path(__file__).parents[1] / "fixtures" / "synthetic_memory_conversation.v1.json"
    conversation = load_synthetic_conversation(fixture)
    manifest = build_synthetic_manifest(
        conversation,
        campaign_id=CANDIDATE,
        destination_content_scope_id=SCOPE,
        fingerprint_key=b"f" * 32,
        expires_at=datetime(2026, 9, 13, tzinfo=UTC),
        max_model_spend_microusd=25_000,
        max_attempts=2,
    )
    verify_synthetic_manifest(conversation, manifest, fingerprint_key=b"f" * 32)
    requests = build_archive_requests(
        conversation, manifest, fingerprint_key=b"f" * 32
    )

    assert len(requests) == len(conversation.messages) == 9
    assert all(request.content_classification == "memory_import.protected" for request in requests)
    assert len({request.idempotency_key for request in requests}) == len(requests)
    assert len({record.content_commitment for record in manifest.records}) == len(manifest.records)
    assert any(not record.displayed for record in manifest.records)

    changed = conversation.model_copy(
        update={
            "messages": (
                conversation.messages[0].model_copy(update={"content": "changed"}),
                *conversation.messages[1:],
            )
        }
    )
    with pytest.raises(ValueError, match="does not match"):
        verify_synthetic_manifest(changed, manifest, fingerprint_key=b"f" * 32)


def test_synthetic_requests_receive_independent_encrypted_evidence_envelopes() -> None:
    fixture = Path(__file__).parents[1] / "fixtures" / "synthetic_memory_conversation.v1.json"
    conversation = load_synthetic_conversation(fixture)
    manifest = build_synthetic_manifest(
        conversation,
        campaign_id=CANDIDATE,
        destination_content_scope_id=SCOPE,
        fingerprint_key=b"f" * 32,
        expires_at=datetime(2026, 9, 13, tzinfo=UTC),
        max_model_spend_microusd=25_000,
        max_attempts=2,
    )
    requests = build_archive_requests(
        conversation, manifest, fingerprint_key=b"f" * 32
    )
    backend = _ArchiveBackend()
    scope = OriginScopeV1(
        tenant_account_id=UUID(int=10),
        node_id=UUID(int=11),
        node_tenure_id=UUID(int=12),
        tenure_epoch=1,
        security_realm_id=UUID(int=13),
        storage_epoch=1,
    )
    encryptor = RealmArchiveEncryptor(
        backend,
        RealmArchiveIdentityV1(
            target_scope=scope,
            evidence_key_arn=KEY_ARN,
            record_version=1,
        ),
        commitment_key=b"c" * 32,
    )

    for index, request in enumerate(requests, start=100):
        envelope = encryptor.encrypt(
            evidence_id=UUID(int=index),
            representation_id=UUID(int=index + 100),
            key_ref=UUID(int=index + 200),
            plaintext=request.plaintext,
            authenticated_header=request.authenticated_header,
            request_commitment="a" * 64,
        )
        assert AESGCM(b"d" * 32).decrypt(
            base64.b64decode(envelope.payload_binding.content_nonce_b64),
            base64.b64decode(envelope.payload_binding.ciphertext_b64),
            request.authenticated_header,
        ) == request.plaintext
        assert request.plaintext not in envelope.model_dump_json().encode()

    assert len(backend.envelopes) == len(requests)
    assert len(backend.contexts) == len(requests)
    assert len({context["evidence_id"] for context in backend.contexts}) == len(requests)


def test_context_compiler_enforces_one_total_budget() -> None:
    budget = ContextBudgetV1(
        total_tokens=1_000,
        instructions_tokens=200,
        tools_tokens=100,
        input_tokens=100,
        recent_turn_tokens=100,
        output_reserve_tokens=200,
        reasoning_reserve_tokens=100,
        safety_headroom_tokens=50,
    )
    ordinary = ContextItemV1(
        claim_id=CLAIM,
        candidate_id=CANDIDATE,
        candidate_version=1,
        protection_class=ProtectionClass.ORDINARY_PRIVATE,
        text="ordinary",
        source_evidence_ids=(EVIDENCE,),
        estimated_tokens=100,
        relevance_millionths=900_000,
    )
    protected = ordinary.model_copy(
        update={
            "claim_id": UUID("00000000-0000-4000-8000-000000000005"),
            "protection_class": ProtectionClass.PROTECTED,
            "text": "protected",
            "estimated_tokens": 100,
            "relevance_millionths": 800_000,
        }
    )
    compiled = compile_context((protected, ordinary), budget)
    assert budget.memory_tokens == 150
    assert compiled.items == (ordinary,)
    assert compiled.omitted_claim_ids == (protected.claim_id,)


def test_fixed_components_can_consume_the_entire_context_budget() -> None:
    budget = ContextBudgetV1(
        total_tokens=256,
        instructions_tokens=100,
        tools_tokens=50,
        input_tokens=25,
        recent_turn_tokens=25,
        output_reserve_tokens=50,
        reasoning_reserve_tokens=25,
        safety_headroom_tokens=25,
    )
    assert budget.memory_tokens == 0
    assert compile_context((), budget).memory_tokens_available == 0
