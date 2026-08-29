from __future__ import annotations

import hashlib
import json
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest
from pydantic import TypeAdapter, ValidationError
from sqlalchemy import create_engine, func, select, text, update
from sqlalchemy.exc import DBAPIError

from lucy.actions import ActionControlService
from lucy.approvals import ApprovalService
from lucy.archive import (
    CaptureModeInput,
    ConversationArchiveService,
    ConversationMessageArchiveInput,
)
from lucy.archive_crypto import (
    AWS_KMS_ALGORITHM,
    AwsKmsEnvelopeCipher,
    EnvelopeCipher,
    MemoryArchiveKeyStore,
)
from lucy.contracts import (
    ApprovalDecision,
    ApprovalDecisionV1,
    ApprovalStatus,
    HumanActorType,
    OperationOutcome,
    RejoiningState,
)
from lucy.contracts.v1 import ConversationEvidenceV1, ConversationMessageV1
from lucy.corrections import CorrectionService
from lucy.db import create_session_factory
from lucy.db.models import (
    ActionExecutionRow,
    ApprovalRequestRow,
    AuditEventRow,
    BudgetAccountRow,
    ConversationCaptureStateRow,
    ConversationTurnRow,
    EvidencePayloadRow,
    EvidenceRow,
    EvidenceTombstoneRow,
    LifecycleRow,
    MemoryClaimRow,
    MemoryCorrectionRow,
    MemoryRelationshipRow,
    MemoryWriteProposalRow,
    OperationRow,
    StartupRunRow,
    WorkingContextRow,
)
from lucy.evidence import (
    EvidenceDeletionRequest,
    EvidenceRetrievalRequest,
    EvidenceService,
)
from lucy.memory import MemoryService
from lucy.model_execution import (
    MODEL,
    RESERVATION_MICROUSD,
    ModelExecutionBegin,
    ModelExecutionService,
    ModelExecutionSettlement,
    ModelUsage,
)
from lucy.policy import ActionIntent
from lucy.proposals import MemoryProposalInput, MemoryProposalService
from lucy.recovery import RecoveryService
from lucy.rejoining import RejoiningService
from lucy.vertical_slice import ImportRequest, VerticalSliceService

DATABASE_URL = os.getenv("LUCY_TEST_DATABASE_URL")
OWNER_DATABASE_URL = os.getenv("LUCY_TEST_OWNER_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="requires PostgreSQL integration database")


@pytest.fixture(autouse=True)
def reset_synthetic_database() -> None:
    if OWNER_DATABASE_URL is None:
        pytest.skip("requires PostgreSQL owner URL for isolated test reset")
    engine = create_engine(OWNER_DATABASE_URL)
    with engine.begin() as connection:
        connection.execute(
            text(
                "TRUNCATE lucy.action_executions, lucy.memory_write_proposals, "
                "lucy.memory_corrections, "
                "lucy.evidence_tombstones, lucy.evidence_payloads, "
                "lucy.conversation_turns, lucy.conversation_capture_states, "
                "lucy.startup_runs, lucy.working_contexts, "
                "lucy.memory_relationships, "
                "lucy.memory_entities, lucy.audit_events, lucy.approval_requests, "
                "lucy.budget_reservations, lucy.memory_claims, "
                "lucy.evidence, lucy.operations, lucy.audit_head, lucy.lifecycle, "
                "lucy.budget_accounts CASCADE"
            )
        )
        connection.execute(
            text(
                "INSERT INTO lucy.lifecycle (singleton, state, version, updated_at) "
                "VALUES (true, 'offline', 0, now())"
            )
        )
        connection.execute(
            text(
                "INSERT INTO lucy.audit_head (singleton, last_sequence, last_hash) "
                "VALUES (true, 0, repeat('0', 64))"
            )
        )
        connection.execute(
            text(
                "INSERT INTO lucy.budget_accounts "
                "(name, limit_microusd, reserved_microusd, spent_microusd) "
                "VALUES ('model.daily', 1000000, 0, 0)"
            )
        )
        connection.execute(
            text(
                "INSERT INTO lucy.budget_accounts "
                "(name, limit_microusd, reserved_microusd, spent_microusd) "
                "VALUES ('action.daily', 1000000, 0, 0)"
            )
        )
    engine.dispose()


def _request() -> ImportRequest:
    return _tea_request("acceptance:synthetic-conversation:1", "Earl Grey", "synthetic-1")


def _archive_dependencies() -> tuple[EnvelopeCipher, MemoryArchiveKeyStore]:
    return (
        EnvelopeCipher(b"k" * 32, b"c" * 32, kek_version="acceptance-v1"),
        MemoryArchiveKeyStore(),
    )


def _tea_request(idempotency_key: str, tea: str, message_id: str) -> ImportRequest:
    occurred_at = datetime(2026, 8, 26, 12, tzinfo=UTC)
    message = ConversationMessageV1(
        message_id=message_id,
        role="user",
        content=f"My favorite tea is {tea}.",
        occurred_at=occurred_at,
    )
    messages = [message.model_dump(mode="json")]
    digest = hashlib.sha256(
        json.dumps(messages, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return ImportRequest(
        idempotency_key=idempotency_key,
        evidence=ConversationEvidenceV1(
            evidence_id=uuid4(),
            source="synthetic",
            source_conversation_id="acceptance-1",
            captured_at=occurred_at,
            messages=(message,),
            content_sha256=digest,
        ),
        subject="user",
        predicate="favorite_tea",
        object=tea,
        confidence=0.9,
        reserve_microusd=5000,
        settle_microusd=3200,
    )


def test_import_restart_and_exactly_once_recovery() -> None:
    assert DATABASE_URL is not None
    sessions = create_session_factory(DATABASE_URL)
    first = VerticalSliceService(sessions).import_synthetic_conversation(_request())

    # A new service instance represents a process restart. The same idempotency
    # key must return the durable result without repeating any side effect.
    restarted = VerticalSliceService(create_session_factory(DATABASE_URL))
    replay = restarted.import_synthetic_conversation(_request())
    assert replay.replayed is True
    assert replay.operation_id == first.operation_id

    with sessions() as session:
        assert session.scalar(select(func.count()).select_from(EvidenceRow)) == 1
        assert session.scalar(select(func.count()).select_from(MemoryClaimRow)) == 1
        assert session.scalar(select(func.count()).select_from(AuditEventRow)) == 7
        budget = session.get(BudgetAccountRow, "model.daily")
        assert budget is not None
        assert budget.reserved_microusd == 0
        assert budget.spent_microusd == 3200

        events = list(session.scalars(select(AuditEventRow).order_by(AuditEventRow.sequence)))
        previous = "0" * 64
        for event in events:
            assert event.previous_hash == previous
            material = {
                "sequence": event.sequence,
                "operation_id": str(event.operation_id),
                "event_type": event.event_type,
                "occurred_at": event.occurred_at.isoformat(),
                "payload": event.payload,
                "previous_hash": event.previous_hash,
            }
            recomputed = hashlib.sha256(
                json.dumps(
                    material, sort_keys=True, separators=(",", ":"), ensure_ascii=False
                ).encode()
            ).hexdigest()
            assert event.event_hash == recomputed
            previous = event.event_hash


def test_telegram_messages_are_archived_once_without_creating_claims() -> None:
    assert DATABASE_URL is not None
    sessions = create_session_factory(DATABASE_URL)
    cipher, keys = _archive_dependencies()
    request = ConversationMessageArchiveInput(
        platform="telegram",
        source_conversation_id="session-1",
        source_turn_id="turn-1",
        source_message_id="turn-1:user",
        role="user",
        content="Please remember our conversations by default.",
    )
    first = ConversationArchiveService(sessions, cipher, keys).preserve_message(
        "hermes-transcript:telegram:session-1:turn-1:user", request
    )
    replay = ConversationArchiveService(
        create_session_factory(DATABASE_URL), cipher, keys
    ).preserve_message(
        "hermes-transcript:telegram:session-1:turn-1:user", request
    )
    assistant = ConversationArchiveService(sessions, cipher, keys).preserve_message(
        "hermes-transcript:telegram:session-1:turn-1:assistant",
        request.model_copy(
            update={
                "source_message_id": "turn-1:assistant",
                "role": "assistant",
                "content": "I will remember by default.",
            }
        ),
    )

    assert first.archived is True
    assert replay.replayed is True
    assert replay.evidence_id == first.evidence_id
    assert assistant.turn_committed is True
    assert first.evidence_id is not None
    with sessions() as session:
        assert session.scalar(select(func.count()).select_from(EvidenceRow)) == 2
        assert session.scalar(select(func.count()).select_from(MemoryClaimRow)) == 0
        assert session.scalar(select(func.count()).select_from(AuditEventRow)) == 6
        evidence = session.get(EvidenceRow, first.evidence_id)
        payload = session.get(EvidencePayloadRow, first.evidence_id)
        assert evidence is not None
        assert payload is not None
        assert evidence.source == "hermes"
        assert evidence.source_conversation_id == "telegram:session-1"
        assert evidence.content["encrypted"] is True
        assert evidence.content["role"] == "user"
        assert "content" not in evidence.content
        assert request.content.encode() not in payload.ciphertext
        assert keys.get(payload.key_ref) is not None
        turn = session.get(
            ConversationTurnRow,
            {
                "platform": "telegram",
                "source_conversation_id": "session-1",
                "source_turn_id": "turn-1",
            },
        )
        assert turn is not None and turn.status == "committed"
        assert turn.committed_at is not None


def test_archive_idempotency_collision_is_rejected() -> None:
    assert DATABASE_URL is not None
    sessions = create_session_factory(DATABASE_URL)
    cipher, keys = _archive_dependencies()
    key = "hermes-transcript:telegram:session-1:turn-1:user"
    original = ConversationMessageArchiveInput(
        platform="telegram",
        source_conversation_id="session-1",
        source_turn_id="turn-1",
        source_message_id="turn-1:user",
        role="user",
        content="Original message",
    )
    collision = original.model_copy(update={"content": "Different message"})
    ConversationArchiveService(sessions, cipher, keys).preserve_message(key, original)
    with pytest.raises(ValueError, match="another message"):
        ConversationArchiveService(sessions, cipher, keys).preserve_message(key, collision)


def test_mocked_aws_kms_archive_round_trip_uses_production_algorithm() -> None:
    assert DATABASE_URL is not None
    key_arn = (
        "arn:aws:kms:us-east-1:123456789012:"
        "key/12345678-1234-1234-1234-123456789012"
    )

    class Kms:
        context: dict[str, str] | None = None

        def generate_data_key(self, **kwargs: Any) -> dict[str, Any]:
            self.context = kwargs["EncryptionContext"]
            return {
                "Plaintext": b"d" * 32,
                "CiphertextBlob": b"kms-wrapped-dek",
                "KeyId": key_arn,
            }

        def decrypt(self, **kwargs: Any) -> dict[str, Any]:
            assert kwargs["EncryptionContext"] == self.context
            assert kwargs["CiphertextBlob"] == b"kms-wrapped-dek"
            return {"Plaintext": b"d" * 32, "KeyId": key_arn}

    sessions = create_session_factory(DATABASE_URL)
    keys = MemoryArchiveKeyStore()
    cipher = AwsKmsEnvelopeCipher(Kms(), key_arn=key_arn, commitment_key=b"c" * 32)
    archived = ConversationArchiveService(sessions, cipher, keys).preserve_message(
        "aws-kms:telegram:session-1:turn-1:user",
        ConversationMessageArchiveInput(
            platform="telegram",
            source_conversation_id="session-1",
            source_turn_id="turn-1",
            source_message_id="turn-1:user",
            role="user",
            content="Synthetic AWS KMS evidence.",
        ),
    )
    assert archived.evidence_id is not None
    retrieved = EvidenceService(sessions, cipher, keys).retrieve(
        "aws-kms:owner-read:1",
        EvidenceRetrievalRequest(
            evidence_id=archived.evidence_id,
            reason="owner_review",
        ),
        owner=True,
    )
    assert retrieved.message.content == "Synthetic AWS KMS evidence."
    with sessions() as session:
        payload = session.get(EvidencePayloadRow, archived.evidence_id)
        assert payload is not None and payload.algorithm == AWS_KMS_ALGORITHM


def test_owner_deletion_crypto_shreds_and_invalidates_all_derived_memory() -> None:
    assert DATABASE_URL is not None
    sessions = create_session_factory(DATABASE_URL)
    cipher, keys = _archive_dependencies()
    archived = ConversationArchiveService(sessions, cipher, keys).preserve_message(
        "hermes-transcript:telegram:session-1:turn-1:user",
        ConversationMessageArchiveInput(
            platform="telegram",
            source_conversation_id="session-1",
            source_turn_id="turn-1",
            source_message_id="turn-1:user",
            role="user",
            content="My favorite tea is Earl Grey.",
        ),
    )
    assert archived.evidence_id is not None
    proposal = MemoryProposalService(sessions).submit(
        "proposal:encrypted-tea",
        MemoryProposalInput(
            evidence_id=archived.evidence_id,
            subject="user",
            predicate="favorite_tea",
            object="Earl Grey",
            confidence=0.9,
        ),
    )
    ApprovalService(sessions).decide(
        idempotency_key="proposal:encrypted-tea:approve",
        approval_id=proposal.approval_id,
        decision=ApprovalDecision.APPROVE,
        decided_by="synthetic-owner",
        actor_type=HumanActorType.OWNER,
    )
    applied = MemoryProposalService(sessions).apply(proposal.proposal_id)
    assert applied.claim_id is not None
    MemoryService(sessions).materialize_claim(applied.claim_id)
    MemoryService(sessions).build_context("Earl Grey", persist=True)

    evidence = EvidenceService(sessions, cipher, keys)
    owner_retrieval = evidence.retrieve(
        "evidence-owner-read:1",
        EvidenceRetrievalRequest(
            evidence_id=archived.evidence_id,
            reason="owner_review",
        ),
        owner=True,
    )
    assert owner_retrieval.message.content == "My favorite tea is Earl Grey."
    with pytest.raises(ValueError, match="another evidence retrieval"):
        evidence.retrieve(
            "evidence-owner-read:1",
            EvidenceRetrievalRequest(
                evidence_id=archived.evidence_id,
                reason="owner_export",
            ),
            owner=True,
        )
    with pytest.raises(PermissionError, match="provenance-linked claim"):
        evidence.retrieve(
            "evidence-autonomous-read-without-claim:1",
            EvidenceRetrievalRequest(
                evidence_id=archived.evidence_id,
                reason="resolve_ambiguity",
            ),
            owner=False,
        )
    retrieved = evidence.retrieve(
        "evidence-read:1",
        EvidenceRetrievalRequest(
            evidence_id=archived.evidence_id,
            claim_id=applied.claim_id,
            reason="verify_exact_wording",
        ),
        owner=False,
    )
    assert retrieved.message.content == "My favorite tea is Earl Grey."
    deleted = evidence.delete(
        "evidence-delete:1",
        EvidenceDeletionRequest(
            evidence_id=archived.evidence_id,
            reason="owner_request",
        ),
    )
    replay = evidence.delete(
        "evidence-delete:1",
        EvidenceDeletionRequest(
            evidence_id=archived.evidence_id,
            reason="owner_request",
        ),
    )
    with pytest.raises(ValueError, match="another evidence deletion"):
        evidence.delete(
            "evidence-delete:1",
            EvidenceDeletionRequest(
                evidence_id=archived.evidence_id,
                reason="sensitive_data",
            ),
        )
    assert deleted.key_destroyed is True
    assert replay.replayed is True
    assert deleted.derived_summary["claims_invalidated"] == 1
    assert deleted.derived_summary["proposals_rejected"] == 1
    with pytest.raises(LookupError, match="deleted"):
        evidence.retrieve(
            "evidence-read:after-delete",
            EvidenceRetrievalRequest(
                evidence_id=archived.evidence_id,
                claim_id=applied.claim_id,
                reason="verify_exact_wording",
            ),
            owner=False,
        )
    with sessions() as session:
        assert session.get(EvidencePayloadRow, archived.evidence_id) is None
        assert session.get(EvidenceTombstoneRow, archived.evidence_id) is not None
        claim = session.get(MemoryClaimRow, applied.claim_id)
        proposal_row = session.get(MemoryWriteProposalRow, proposal.proposal_id)
        turn = session.get(
            ConversationTurnRow,
            {
                "platform": "telegram",
                "source_conversation_id": "session-1",
                "source_turn_id": "turn-1",
            },
        )
        assert claim is not None and claim.status == "invalidated"
        assert claim.object == "[redacted]"
        assert proposal_row is not None and proposal_row.status == "rejected"
        assert proposal_row.object == "[redacted]"
        assert turn is not None and turn.status == "redacted"
        assert session.scalar(select(func.count()).select_from(WorkingContextRow)) == 0


def test_capture_mode_defaults_on_and_off_record_skips_evidence() -> None:
    assert DATABASE_URL is not None
    sessions = create_session_factory(DATABASE_URL)
    cipher, keys = _archive_dependencies()
    archive = ConversationArchiveService(sessions, cipher, keys)
    assert archive.capture_mode("telegram", "session-1").capture_enabled is True
    disabled = archive.set_capture_mode(
        "capture-mode:session-1:off",
        CaptureModeInput(
            platform="telegram",
            source_conversation_id="session-1",
            capture_enabled=False,
        ),
    )
    assert disabled.capture_enabled is False
    with pytest.raises(ValueError, match="another capture transition"):
        archive.set_capture_mode(
            "capture-mode:session-1:off",
            CaptureModeInput(
                platform="telegram",
                source_conversation_id="session-1",
                capture_enabled=True,
            ),
        )
    skipped = archive.preserve_message(
        "hermes-transcript:telegram:session-1:off:user",
        ConversationMessageArchiveInput(
            platform="telegram",
            source_conversation_id="session-1",
            source_turn_id="off",
            source_message_id="off:user",
            role="user",
            content="This must not enter Lucy's archive.",
        ),
    )
    assert skipped.archived is False and skipped.capture_enabled is False
    with sessions() as session:
        assert session.scalar(select(func.count()).select_from(EvidenceRow)) == 0
        state = session.get(
            ConversationCaptureStateRow,
            {"platform": "telegram", "source_conversation_id": "session-1"},
        )
        assert state is not None and state.capture_enabled is False


def test_startup_reconciliation_finishes_interrupted_key_destruction() -> None:
    assert DATABASE_URL is not None
    sessions = create_session_factory(DATABASE_URL)
    cipher, keys = _archive_dependencies()
    archived = ConversationArchiveService(sessions, cipher, keys).preserve_message(
        "hermes-transcript:telegram:session-recovery:turn-1:user",
        ConversationMessageArchiveInput(
            platform="telegram",
            source_conversation_id="session-recovery",
            source_turn_id="turn-1",
            source_message_id="turn-1:user",
            role="user",
            content="Delete this even if the process stops midway.",
        ),
    )
    assert archived.evidence_id is not None
    with sessions() as session:
        payload = session.get(EvidencePayloadRow, archived.evidence_id)
        assert payload is not None
        key_ref = payload.key_ref
    assert keys.delete(key_ref) is True

    evidence = EvidenceService(sessions, cipher, keys)
    assert evidence.reconcile_missing_keys() == 1
    assert evidence.reconcile_missing_keys() == 0
    with sessions() as session:
        assert session.get(EvidencePayloadRow, archived.evidence_id) is None
        tombstone = session.get(EvidenceTombstoneRow, archived.evidence_id)
        assert tombstone is not None
        assert tombstone.reason_category == "sensitive_data"
        turn = session.get(
            ConversationTurnRow,
            {
                "platform": "telegram",
                "source_conversation_id": "session-recovery",
                "source_turn_id": "turn-1",
            },
        )
        assert turn is not None and turn.status == "redacted"


def test_human_approval_is_durable_and_idempotent() -> None:
    assert DATABASE_URL is not None
    sessions = create_session_factory(DATABASE_URL)
    service = ApprovalService(sessions)
    requested = service.request(
        idempotency_key="approval:request:1",
        action_type="telegram.send",
        action_payload={"recipient": "synthetic-only"},
    )
    replay = service.request(
        idempotency_key="approval:request:1",
        action_type="telegram.send",
        action_payload={"recipient": "synthetic-only"},
    )
    assert replay.replayed is True
    assert replay.approval_id == requested.approval_id

    decided = service.decide(
        idempotency_key="approval:decision:1",
        approval_id=requested.approval_id,
        decision=ApprovalDecision.APPROVE,
        decided_by="synthetic-owner",
        actor_type=HumanActorType.OWNER,
        reason="integration acceptance",
    )
    decision_replay = service.decide(
        idempotency_key="approval:decision:1",
        approval_id=requested.approval_id,
        decision=ApprovalDecision.APPROVE,
        decided_by="synthetic-owner",
        actor_type=HumanActorType.OWNER,
    )
    assert decided.status == ApprovalStatus.APPROVED
    assert decision_replay.replayed is True
    with pytest.raises(RuntimeError, match="conflicting status"):
        service.decide(
            idempotency_key="approval:decision:conflict",
            approval_id=requested.approval_id,
            decision=ApprovalDecision.DENY,
            decided_by="synthetic-owner",
            actor_type=HumanActorType.OWNER,
        )
    with sessions() as session:
        row = session.get(ApprovalRequestRow, requested.approval_id)
        assert row is not None
        assert row.actor_type == HumanActorType.OWNER
        assert row.version == 1


def test_model_actor_is_rejected_by_contract() -> None:
    with pytest.raises(ValidationError):
        TypeAdapter(ApprovalDecisionV1).validate_python(
            {
                "approval_id": str(uuid4()),
                "decision": "approve",
                "decided_by": "model-instance",
                "actor_type": "model",
            }
        )


def test_ambiguous_restart_degrades_without_retrying() -> None:
    assert DATABASE_URL is not None
    sessions = create_session_factory(DATABASE_URL)
    pending_id = uuid4()
    with sessions.begin() as session:
        lifecycle = session.get(LifecycleRow, True)
        assert lifecycle is not None
        lifecycle.state = "rejoining"
        lifecycle.version = 1
        session.add(
            OperationRow(
                id=pending_id,
                idempotency_key="external:synthetic:uncertain",
                outcome=OperationOutcome.PENDING,
                result=None,
                created_at=datetime.now(UTC),
                completed_at=None,
            )
        )

    restarted = RecoveryService(create_session_factory(DATABASE_URL))
    assert restarted.mark_ambiguous_pending() == 1
    assert restarted.mark_ambiguous_pending() == 0
    with sessions() as session:
        operation = session.get(OperationRow, pending_id)
        lifecycle = session.get(LifecycleRow, True)
        assert operation is not None and lifecycle is not None
        assert operation.outcome == OperationOutcome.AMBIGUOUS
        assert operation.result == {
            "reason": "outcome_unknown_after_restart",
            "retried": False,
        }
        assert lifecycle.state == "degraded"
        assert session.scalar(
            select(func.count()).select_from(AuditEventRow).where(
                AuditEventRow.event_type == "operation.ambiguous"
            )
        ) == 1


def test_three_layer_memory_projection_survives_restart_without_raw_archive() -> None:
    assert DATABASE_URL is not None
    sessions = create_session_factory(DATABASE_URL)
    imported = VerticalSliceService(sessions).import_synthetic_conversation(_request())
    memory = MemoryService(sessions)
    graph = memory.materialize_claim(imported.claim_id)

    restarted = MemoryService(create_session_factory(DATABASE_URL))
    replay = restarted.materialize_claim(imported.claim_id)
    context = restarted.build_context("Earl Grey", persist=True)

    assert replay.replayed is True
    assert replay.relationship_id == graph.relationship_id
    assert len(context.claims) == 1
    projection = context.claims[0]
    assert projection["object"] == "Earl Grey"
    assert projection["evidence_id"] == str(imported.evidence_id)
    assert "messages" not in projection
    assert "content" not in projection
    restarted.build_context("Earl Grey")
    with sessions() as session:
        assert session.scalar(select(func.count()).select_from(WorkingContextRow)) == 1


def test_archive_evidence_rejects_mutation() -> None:
    assert DATABASE_URL is not None
    sessions = create_session_factory(DATABASE_URL)
    imported = VerticalSliceService(sessions).import_synthetic_conversation(_request())
    with (
        pytest.raises(DBAPIError, match="permission denied|append-only"),
        sessions.begin() as session,
    ):
        session.execute(
            update(EvidenceRow)
            .where(EvidenceRow.id == imported.evidence_id)
            .values(source="hermes")
        )


def test_concurrent_graph_materialization_creates_one_relationship() -> None:
    assert DATABASE_URL is not None
    sessions = create_session_factory(DATABASE_URL)
    imported = VerticalSliceService(sessions).import_synthetic_conversation(_request())

    def materialize() -> str:
        result = MemoryService(create_session_factory(DATABASE_URL)).materialize_claim(
            imported.claim_id
        )
        return str(result.relationship_id)

    with ThreadPoolExecutor(max_workers=2) as executor:
        ids = list(executor.map(lambda _: materialize(), range(2)))
    assert len(set(ids)) == 1


HERMES_COMMIT = "fcbd1076a93841fa88855acce810e342a5b78101"


def test_rejoining_reaches_ready_and_can_restart_from_ready() -> None:
    assert DATABASE_URL is not None
    sessions = create_session_factory(DATABASE_URL)
    service = RejoiningService(sessions, expected_hermes_commit=HERMES_COMMIT)
    first = service.run(observed_hermes_commit=HERMES_COMMIT)
    second = RejoiningService(
        create_session_factory(DATABASE_URL), expected_hermes_commit=HERMES_COMMIT
    ).run(observed_hermes_commit=HERMES_COMMIT)
    assert first.state == RejoiningState.READY
    assert second.state == RejoiningState.READY
    assert all(value == "ok" for value in second.checks.values())


def test_rejoining_pin_mismatch_forces_degraded() -> None:
    assert DATABASE_URL is not None
    result = RejoiningService(
        create_session_factory(DATABASE_URL), expected_hermes_commit=HERMES_COMMIT
    ).run(observed_hermes_commit="0" * 40)
    assert result.state == RejoiningState.DEGRADED
    assert result.checks["hermes_pin"] == "mismatch"


def test_rejoining_invalid_budget_forces_degraded() -> None:
    assert DATABASE_URL is not None
    sessions = create_session_factory(DATABASE_URL)
    with sessions.begin() as session:
        budget = session.get(BudgetAccountRow, "model.daily")
        assert budget is not None
        budget.limit_microusd = 1
        budget.spent_microusd = 2
    result = RejoiningService(
        sessions, expected_hermes_commit=HERMES_COMMIT
    ).run(observed_hermes_commit=HERMES_COMMIT)
    assert result.state == RejoiningState.DEGRADED
    assert result.checks["budgets"] == "invalid"


def test_rejoining_quarantines_pending_operation_without_retry() -> None:
    assert DATABASE_URL is not None
    sessions = create_session_factory(DATABASE_URL)
    pending_id = uuid4()
    with sessions.begin() as session:
        session.add(
            OperationRow(
                id=pending_id, idempotency_key="startup:uncertain-effect",
                outcome=OperationOutcome.PENDING, result=None,
                created_at=datetime.now(UTC), completed_at=None,
            )
        )
    result = RejoiningService(
        sessions, expected_hermes_commit=HERMES_COMMIT
    ).run(observed_hermes_commit=HERMES_COMMIT)
    assert result.state == RejoiningState.DEGRADED
    assert result.ambiguous_count == 1
    with sessions() as session:
        operation = session.get(OperationRow, pending_id)
        assert operation is not None
        assert operation.outcome == OperationOutcome.AMBIGUOUS
        assert operation.result is not None and operation.result["retried"] is False


def test_rejoining_detects_broken_audit_head_without_extending_chain() -> None:
    assert DATABASE_URL is not None and OWNER_DATABASE_URL is not None
    sessions = create_session_factory(DATABASE_URL)
    VerticalSliceService(sessions).import_synthetic_conversation(_request())
    with sessions() as session:
        before = session.scalar(select(func.count()).select_from(AuditEventRow))
    owner = create_engine(OWNER_DATABASE_URL)
    with owner.begin() as connection:
        connection.execute(text("UPDATE lucy.audit_head SET last_hash = repeat('f', 64)"))
    owner.dispose()
    result = RejoiningService(
        sessions, expected_hermes_commit=HERMES_COMMIT
    ).run(observed_hermes_commit=HERMES_COMMIT)
    assert result.state == RejoiningState.DEGRADED
    assert result.checks["audit_chain"] == "audit_head_mismatch"
    with sessions() as session:
        assert session.scalar(select(func.count()).select_from(AuditEventRow)) == before
        assert session.scalar(select(func.count()).select_from(StartupRunRow)) == 1


def test_approved_correction_supersedes_without_erasing_history() -> None:
    assert DATABASE_URL is not None
    sessions = create_session_factory(DATABASE_URL)
    first = VerticalSliceService(sessions).import_synthetic_conversation(_request())
    MemoryService(sessions).materialize_claim(first.claim_id)
    with sessions.begin() as session:
        lifecycle = session.get(LifecycleRow, True)
        assert lifecycle is not None
        lifecycle.state = "offline"
    replacement = VerticalSliceService(sessions).import_synthetic_conversation(
        _tea_request("acceptance:synthetic-conversation:2", "English Breakfast", "synthetic-2")
    )
    correction_service = CorrectionService(sessions)
    proposed = correction_service.propose(
        idempotency_key="correction:tea:1", old_claim_id=first.claim_id,
        new_evidence_id=replacement.evidence_id,
        replacement_object="English Breakfast", confidence=0.95,
    )
    with pytest.raises(PermissionError):
        correction_service.apply(proposed.correction_id)
    ApprovalService(sessions).decide(
        idempotency_key="correction:tea:decision", approval_id=proposed.approval_id,
        decision=ApprovalDecision.APPROVE, decided_by="synthetic-owner",
        actor_type=HumanActorType.OWNER,
    )
    applied = correction_service.apply(proposed.correction_id)
    replay = CorrectionService(create_session_factory(DATABASE_URL)).apply(
        proposed.correction_id
    )
    assert applied.status == "applied" and replay.replayed is True
    context = MemoryService(sessions).build_context("tea")
    assert [claim["object"] for claim in context.claims] == ["English Breakfast"]
    with sessions() as session:
        old = session.get(MemoryClaimRow, first.claim_id)
        new = session.get(MemoryClaimRow, applied.new_claim_id)
        correction = session.get(MemoryCorrectionRow, proposed.correction_id)
        relationship = session.scalar(select(MemoryRelationshipRow).where(
            MemoryRelationshipRow.claim_id == first.claim_id))
        assert old is not None and old.status == "superseded"
        assert new is not None and new.supersedes_claim_id == old.id
        assert correction is not None and correction.new_evidence_id == replacement.evidence_id
        assert relationship is not None and relationship.valid_to is not None


def test_model_memory_proposal_requires_human_approval_and_replays() -> None:
    assert DATABASE_URL is not None
    sessions = create_session_factory(DATABASE_URL)
    imported = VerticalSliceService(sessions).import_synthetic_conversation(_request())
    proposals = MemoryProposalService(sessions)
    candidate = MemoryProposalInput(
        evidence_id=imported.evidence_id, subject="user", predicate="likes_tea",
        object="Earl Grey", confidence=0.8,
    )
    proposed = proposals.submit("hermes:proposal:1", candidate)
    duplicate = proposals.submit("hermes:proposal:1", candidate)
    assert duplicate.replayed is True and duplicate.proposal_id == proposed.proposal_id
    with pytest.raises(PermissionError):
        proposals.apply(proposed.proposal_id)
    ApprovalService(sessions).decide(
        idempotency_key="hermes:proposal:decision:1", approval_id=proposed.approval_id,
        decision=ApprovalDecision.APPROVE, decided_by="synthetic-owner",
        actor_type=HumanActorType.OWNER,
    )
    applied = proposals.apply(proposed.proposal_id)
    replay = MemoryProposalService(create_session_factory(DATABASE_URL)).apply(
        proposed.proposal_id
    )
    assert applied.status == "applied" and replay.replayed is True
    with sessions() as session:
        row = session.get(MemoryWriteProposalRow, proposed.proposal_id)
        claim = session.get(MemoryClaimRow, applied.claim_id)
        assert row is not None and claim is not None
        assert claim.evidence_id == imported.evidence_id


def test_action_requires_approval_reserves_before_execution_and_settles_once() -> None:
    assert DATABASE_URL is not None
    sessions = create_session_factory(DATABASE_URL)
    actions = ActionControlService(sessions)
    submitted = actions.submit(
        idempotency_key="action:telegram:1",
        intent=ActionIntent(action_type="telegram.send", estimated_microusd=500),
        payload={"recipient": "synthetic", "text": "hello"},
    )
    assert submitted.status == "awaiting_approval" and submitted.approval_id is not None
    with pytest.raises(PermissionError):
        actions.authorize(submitted.action_id)
    ApprovalService(sessions).decide(
        idempotency_key="action:telegram:decision:1", approval_id=submitted.approval_id,
        decision=ApprovalDecision.APPROVE, decided_by="synthetic-owner",
        actor_type=HumanActorType.OWNER,
    )
    reserved = actions.authorize(submitted.action_id)
    assert reserved.status == "reserved" and reserved.reservation_id is not None
    actions.begin_execution(submitted.action_id)
    assert actions.begin_execution(submitted.action_id).replayed is True
    settled = actions.settle(
        submitted.action_id, actual_microusd=320, succeeded=True,
        result={"delivery": "synthetic-ok"},
    )
    replay = actions.settle(
        submitted.action_id, actual_microusd=320, succeeded=True,
        result={"delivery": "synthetic-ok"},
    )
    assert settled.status == "succeeded" and replay.replayed is True
    with sessions() as session:
        budget = session.get(BudgetAccountRow, "action.daily")
        assert budget is not None
        assert budget.reserved_microusd == 0 and budget.spent_microusd == 320


def test_unknown_action_is_denied_without_reservation() -> None:
    assert DATABASE_URL is not None
    result = ActionControlService(create_session_factory(DATABASE_URL)).submit(
        idempotency_key="action:unknown:1",
        intent=ActionIntent(action_type="model.invented", estimated_microusd=100),
        payload={},
    )
    assert result.status == "denied" and result.reservation_id is None


def test_rejoining_marks_executing_action_ambiguous_and_charges_reservation() -> None:
    assert DATABASE_URL is not None
    sessions = create_session_factory(DATABASE_URL)
    actions = ActionControlService(sessions)
    submitted = actions.submit(
        idempotency_key="action:lookup:crash",
        intent=ActionIntent(action_type="memory.lookup", estimated_microusd=700),
        payload={"query": "tea"},
    )
    actions.begin_execution(submitted.action_id)
    with sessions.begin() as session:
        lifecycle = session.get(LifecycleRow, True)
        assert lifecycle is not None
        lifecycle.state = "rejoining"
    result = RejoiningService(
        sessions, expected_hermes_commit=HERMES_COMMIT
    ).run(observed_hermes_commit=HERMES_COMMIT)
    assert result.state == RejoiningState.DEGRADED and result.ambiguous_count == 1
    with sessions() as session:
        action = session.get(ActionExecutionRow, submitted.action_id)
        budget = session.get(BudgetAccountRow, "model.daily")
        assert action is not None and budget is not None
        assert action.status == "ambiguous"
        assert budget.reserved_microusd == 0 and budget.spent_microusd == 700


def test_model_execution_bridge_reserves_executes_and_settles_once() -> None:
    assert DATABASE_URL is not None
    sessions = create_session_factory(DATABASE_URL)
    service = ModelExecutionService(sessions)
    request = ModelExecutionBegin(
        idempotency_key="hermes-model:session-1:request-1",
        model=MODEL,
        reservation_microusd=RESERVATION_MICROUSD,
        session_id="session-1",
        api_request_id="request-1",
    )
    begun = service.begin(request)
    duplicate = service.begin(request)
    assert begun.status == "executing" and begun.execute is True
    assert duplicate.action_id == begun.action_id
    assert duplicate.status == "executing" and duplicate.execute is False

    settlement = ModelExecutionSettlement(
        action_id=begun.action_id,
        actual_microusd=12,
        succeeded=True,
        usage=ModelUsage(
            input_tokens=100,
            output_tokens=20,
            reasoning_tokens=5,
            provider_cost_microusd=12,
        ),
    )
    settled = service.settle(settlement)
    replay = service.settle(settlement)
    assert settled.status == "succeeded" and settled.replayed is False
    assert replay.status == "succeeded" and replay.replayed is True
    with sessions() as session:
        budget = session.get(BudgetAccountRow, "model.daily")
        assert budget is not None
        assert budget.reserved_microusd == 0 and budget.spent_microusd == 12
