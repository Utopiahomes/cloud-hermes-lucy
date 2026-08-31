from __future__ import annotations

import os
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from threading import Event
from types import SimpleNamespace
from typing import Any
from uuid import UUID, uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import sessionmaker

from lucy.approvals import ApprovalService
from lucy.archive import (
    CaptureModeInput,
    ConversationArchiveService,
    ConversationMessageArchiveInput,
    TurnCaptureInput,
)
from lucy.archive_crypto import EnvelopeCipher, MemoryArchiveKeyStore
from lucy.authorization import (
    SensitiveAction,
    SensitiveActionPermitRequest,
    SensitiveActionPermitService,
    SensitiveActionPermitSigner,
    SensitiveActionPermitVerifier,
)
from lucy.contracts import ApprovalDecision, HumanActorType
from lucy.corrections import CorrectionService
from lucy.db.models import (
    ApprovalRequestRow,
    Base,
    ClaimSourceRow,
    CorrectionSourceRow,
    DeletionJournalBindingRow,
    EvidenceDerivationRow,
    EvidencePayloadRow,
    EvidenceRow,
    EvidenceTombstoneRow,
    MemoryClaimRow,
    MemoryCorrectionRow,
    MemoryWriteProposalRow,
    OperationRow,
    ProposalSourceRow,
    RuntimeAdmissionRow,
    WorkingContextRow,
)
from lucy.deletion_journal import DeletionJournalError, SqliteDeletionJournal
from lucy.evidence import EvidenceDeletionRequest, EvidenceService
from lucy.maintenance import MaintenanceService
from lucy.memory import MemoryService
from lucy.proposals import GatewayMemoryProposalInput, MemoryProposalInput, MemoryProposalService
from lucy.provenance import active_sources, verify_archive_provenance
from lucy.readiness import ReadinessError

URL = os.getenv("LUCY_TEST_DATABASE_URL")
OWNER_URL = os.getenv("LUCY_TEST_OWNER_DATABASE_URL")
PIN = "fcbd1076a93841fa88855acce810e342a5b78101"
pytestmark = pytest.mark.skipif(not URL or not OWNER_URL, reason="isolated PostgreSQL required")


@pytest.fixture
def db(tmp_path: Path) -> Iterator[SimpleNamespace]:
    for value in (URL, OWNER_URL):
        parsed = make_url(value or "")
        assert (parsed.host, parsed.port, parsed.database) == ("127.0.0.1", 54329, "lucy_test")
    owner_engine = create_engine(OWNER_URL)
    app_engine = create_engine(URL)
    owner = sessionmaker(owner_engine, expire_on_commit=False)
    sessions = sessionmaker(app_engine, expire_on_commit=False)
    with owner.begin() as session:
        tables = ", ".join(f"lucy.{table.name}" for table in Base.metadata.sorted_tables)
        session.execute(text(f"TRUNCATE {tables} CASCADE"))
        session.execute(
            text(
                "INSERT INTO lucy.lifecycle VALUES (true,'ready',0,now()); "
                "INSERT INTO lucy.audit_head VALUES (true,0,repeat('0',64)); "
                "INSERT INTO lucy.runtime_admission VALUES (true,'quarantined',NULL,now()); "
                "INSERT INTO lucy.budget_accounts VALUES ('model.daily',1000000,0,0)"
            )
        )
    keys = MemoryArchiveKeyStore()
    journal = SqliteDeletionJournal.initialize(
        tmp_path / "journal.sqlite", registry_id=keys.registry_identity
    )
    head = journal.head()
    with owner.begin() as session:
        session.add(
            DeletionJournalBindingRow(
                singleton=True,
                journal_id=head.journal_id,
                registry_id=head.registry_id,
            )
        )
    cipher = EnvelopeCipher(b"k" * 32, b"c" * 32, kek_version="synthetic-v1")
    private = Ed25519PrivateKey.generate()
    archive = ConversationArchiveService(sessions, cipher, keys, capture_authorized=True)
    issuer = SensitiveActionPermitService(sessions, SensitiveActionPermitSigner(private))
    verifier = SensitiveActionPermitVerifier(private.public_key())
    yield SimpleNamespace(
        sessions=sessions,
        owner=owner,
        keys=keys,
        cipher=cipher,
        archive=archive,
        issuer=issuer,
        verifier=verifier,
        journal=journal,
    )
    app_engine.dispose()
    owner_engine.dispose()


def record(
    db: SimpleNamespace,
    conversation: str,
    turn: str,
    role: str = "user",
    parents: tuple[UUID, ...] = (),
    content: str = "Synthetic violet compass",
) -> UUID:
    db.archive.accept_turn(
        TurnCaptureInput(
            platform="telegram",
            source_conversation_id=conversation,
            source_turn_id=turn,
        )
    )
    result = db.archive.preserve_message(
        f"archive:{conversation}:{turn}:{role}",
        ConversationMessageArchiveInput(
            platform="telegram",
            source_conversation_id=conversation,
            source_turn_id=turn,
            source_message_id=f"{turn}:{role}",
            role=role,
            content=content,
            source_evidence_ids=parents,
        ),
    )
    assert result.evidence_id is not None
    return result.evidence_id


def approve(db: SimpleNamespace, approval_id: UUID) -> None:
    ApprovalService(db.sessions).decide(
        idempotency_key=f"approve:{approval_id}",
        approval_id=approval_id,
        decision=ApprovalDecision.APPROVE,
        decided_by="synthetic-owner",
        actor_type=HumanActorType.OWNER,
    )


def memory(
    db: SimpleNamespace,
    primary: UUID,
    extra: tuple[UUID, ...] = (),
    value: str = "Synthetic violet compass",
    *,
    apply: bool = True,
) -> Any:
    service = MemoryProposalService(db.sessions)
    proposal = service.submit(
        f"proposal:{uuid4()}",
        MemoryProposalInput(
            evidence_id=primary,
            source_evidence_ids=extra,
            subject="owner",
            predicate="likes",
            object=value,
            confidence=0.9,
        ),
    )
    if not apply:
        return proposal
    approve(db, proposal.approval_id)
    result = service.apply(proposal.proposal_id)
    MemoryService(db.sessions).materialize_claim(result.claim_id)
    return result


def delete_request(db: SimpleNamespace, evidence_id: UUID, key: str) -> EvidenceDeletionRequest:
    permit = db.issuer.issue(
        f"permit:{key}",
        SensitiveActionPermitRequest(
            action=SensitiveAction.EVIDENCE_DELETE,
            owner_subject="owner:synthetic",
            owner_interaction_id=f"synthetic:{key}",
            evidence_ids=(evidence_id,),
            reason="owner_request",
        ),
    )
    return EvidenceDeletionRequest(evidence_id=evidence_id, reason="owner_request", permit=permit)


def deleter(db: SimpleNamespace) -> EvidenceService:
    return EvidenceService(db.sessions, None, db.keys, db.verifier, journal=db.journal)


def test_transitive_reply_and_multisource_memory_deletion_preserves_independent_sources(
    db: SimpleNamespace,
) -> None:
    source = record(db, "A", "1")
    independent = record(db, "B", "1", content="Synthetic independent tea")
    reply = record(db, "B", "1", "assistant", (source,))
    later_user = record(db, "B", "2", content="Synthetic follow-up")
    later_reply = record(db, "B", "2", "assistant")
    third_user = record(db, "C", "1")
    third_reply = record(db, "C", "1", "assistant", (later_reply,))
    mixed = memory(db, independent, (third_reply,))
    pending = memory(db, independent, (source,), apply=False)
    unaffected = memory(db, independent, value="Independent tea")
    MemoryService(db.sessions).build_context("violet", persist=True)
    affected = {source, reply, later_reply, third_reply}
    with db.sessions() as session:
        payload_keys = dict(
            session.execute(
                select(
                    EvidencePayloadRow.evidence_id,
                    EvidencePayloadRow.key_ref,
                )
            ).all()
        )
        assert affected <= set(
            session.scalars(
                select(ClaimSourceRow.evidence_id).where(
                    ClaimSourceRow.claim_id == mixed.claim_id,
                )
            )
        )
        verify_archive_provenance(session)
    request = delete_request(db, source, "closure")
    result = deleter(db).delete("closure", request)
    assert result.derived_summary["evidence_records_deleted"] == 4
    assert result.derived_summary["claims_invalidated"] == 1
    assert result.derived_summary["proposals_rejected"] == 2
    assert deleter(db).delete("closure", request).replayed
    with db.sessions() as session:
        tombstones = set(session.scalars(select(EvidenceTombstoneRow.evidence_id)))
        assert tombstones == affected
        assert session.get(MemoryClaimRow, mixed.claim_id).object == "[redacted]"
        assert session.get(MemoryWriteProposalRow, pending.proposal_id).object == "[redacted]"
        assert session.get(ApprovalRequestRow, pending.approval_id).action_payload == {
            "redacted": True
        }
        assert session.scalar(select(func.count()).select_from(WorkingContextRow)) == 0
        assert session.get(MemoryClaimRow, unaffected.claim_id).status == "accepted"
        for item in affected:
            assert session.get(EvidencePayloadRow, item) is None
            assert db.keys.get(payload_keys[item]) is None
        for item in {independent, later_user, third_user}:
            assert session.get(EvidencePayloadRow, item) is not None
            assert db.keys.get(payload_keys[item]) is not None
    assert MemoryService(db.sessions).build_context("violet").claims == []
    assert len(MemoryService(db.sessions).build_context("Independent tea").claims) == 1
    with pytest.raises(PermissionError, match="deleted"):
        memory(db, independent, (third_reply,))
    with pytest.raises(PermissionError, match="deleted"):
        MemoryProposalService(db.sessions).apply(mixed.proposal_id)


def test_corrections_inherit_all_old_claim_sources_not_just_primary(db: SimpleNamespace) -> None:
    source = record(db, "source", "1")
    primary = record(db, "primary", "1")
    replacement = record(db, "replacement", "1")
    old = memory(db, primary, (source,))
    corrections = CorrectionService(db.sessions)
    correction = corrections.propose(
        idempotency_key="correction:multi",
        old_claim_id=old.claim_id,
        new_evidence_id=replacement,
        replacement_object="Synthetic silver compass",
        confidence=0.8,
    )
    approve(db, correction.approval_id)
    applied = corrections.apply(correction.correction_id)
    with db.sessions() as session:
        assert set(
            session.scalars(
                select(CorrectionSourceRow.evidence_id).where(
                    CorrectionSourceRow.correction_id == correction.correction_id,
                )
            )
        ) == {source, primary, replacement}
        assert set(
            session.scalars(
                select(ClaimSourceRow.evidence_id).where(
                    ClaimSourceRow.claim_id == applied.new_claim_id,
                )
            )
        ) == {source, primary, replacement}
    deleter(db).delete("delete:correction", delete_request(db, source, "delete:correction"))
    with db.sessions() as session:
        assert session.get(MemoryClaimRow, applied.new_claim_id).status == "invalidated"
        row = session.get(MemoryCorrectionRow, correction.correction_id)
        assert row.status == "rejected" and row.replacement_object == "[redacted]"
        assert session.get(EvidencePayloadRow, replacement) is not None
    with pytest.raises(PermissionError, match="deleted"):
        corrections.apply(correction.correction_id)


def test_gateway_proposal_cannot_hide_its_current_turn_by_citing_historical_evidence(
    db: SimpleNamespace,
) -> None:
    historical = record(db, "historical", "1")
    current = record(db, "current", "1")
    proposal = MemoryProposalService(db.sessions).submit(
        "gateway:multi",
        GatewayMemoryProposalInput(
            evidence_id=historical,
            source_conversation_id="current",
            source_turn_id="1",
            subject="owner",
            predicate="likes",
            object="Synthetic mixed fact",
            confidence=0.8,
        ),
    )
    with db.sessions() as session:
        assert set(
            session.scalars(
                select(ProposalSourceRow.evidence_id).where(
                    ProposalSourceRow.proposal_id == proposal.proposal_id,
                )
            )
        ) == {historical, current}
    deleter(db).delete("delete:current", delete_request(db, current, "delete:current"))
    with db.sessions() as session:
        assert session.get(MemoryWriteProposalRow, proposal.proposal_id).object == "[redacted]"
        assert session.get(EvidencePayloadRow, historical) is not None


def test_provenance_change_cannot_reuse_proposal_delivery_or_approval(db: SimpleNamespace) -> None:
    a = record(db, "a", "1")
    b = record(db, "b", "1")
    candidate = MemoryProposalInput(
        evidence_id=a,
        source_evidence_ids=(b,),
        subject="owner",
        predicate="likes",
        object="tea",
        confidence=0.7,
    )
    service = MemoryProposalService(db.sessions)
    proposal = service.submit("delivery:stable", candidate)
    assert service.submit("delivery:stable", candidate).replayed
    with pytest.raises(ValueError, match="provenance"):
        service.submit("delivery:stable", candidate.model_copy(update={"source_evidence_ids": ()}))
    approve(db, proposal.approval_id)
    with db.sessions.begin() as session:
        row = session.get(ApprovalRequestRow, proposal.approval_id)
        row.action_payload = {**row.action_payload, "source_evidence_ids": [str(a)]}
    with pytest.raises(PermissionError, match="approval does not match"):
        service.apply(proposal.proposal_id)


@pytest.mark.parametrize("history", ["excluded", "unfinished", "deleted"])
def test_unverified_prior_history_blocks_new_derivatives(
    db: SimpleNamespace,
    history: str,
) -> None:
    if history == "excluded":
        db.archive.set_capture_mode(
            "off",
            CaptureModeInput(
                platform="telegram",
                source_conversation_id="s",
                capture_enabled=False,
            ),
        )
        db.archive.accept_turn(
            TurnCaptureInput(
                platform="telegram",
                source_conversation_id="s",
                source_turn_id="old",
            )
        )
        db.archive.set_capture_mode(
            "on",
            CaptureModeInput(
                platform="telegram",
                source_conversation_id="s",
                capture_enabled=True,
            ),
        )
    else:
        prior = record(db, "s", "old")
        if history == "deleted":
            record(db, "s", "old", "assistant")
            deleter(db).delete("forget", delete_request(db, prior, "forget"))
    current = record(db, "s", "new")
    with pytest.raises(PermissionError, match="clean boundary"):
        record(db, "s", "new", "assistant")
    with pytest.raises(PermissionError, match="clean boundary"):
        MemoryProposalService(db.sessions).submit(
            "unverified:proposal",
            GatewayMemoryProposalInput(
                evidence_id=current,
                source_conversation_id="s",
                source_turn_id="new",
                subject="owner",
                predicate="likes",
                object="tea",
                confidence=0.8,
            ),
        )


def test_late_reply_after_its_current_input_was_deleted_is_rejected_before_encrypting(
    db: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = record(db, "s", "1")
    deleter(db).delete("forget", delete_request(db, source, "forget"))
    monkeypatch.setattr(
        db.cipher, "encrypt", lambda *_: pytest.fail("must reject before encryption")
    )
    with pytest.raises(PermissionError, match="originating retained"):
        record(db, "s", "1", "assistant")


@pytest.mark.parametrize(
    "table",
    [
        "evidence_derivations",
        "claim_sources",
        "proposal_sources",
        "correction_sources",
    ],
)
def test_source_links_are_append_only_even_when_no_rows_match(
    db: SimpleNamespace, table: str
) -> None:
    with pytest.raises(DBAPIError) as caught, db.sessions.begin() as session:
        session.execute(text(f"DELETE FROM lucy.{table}"))
    assert caught.value.orig.sqlstate == "42501"


def test_deleted_secondary_source_is_filtered_even_if_a_projection_is_stale(
    db: SimpleNamespace,
) -> None:
    source = record(db, "a", "1")
    primary = record(db, "b", "1")
    mixed = memory(db, primary, (source,))
    # Model a stale projection/incomplete old cascade, without changing the graph.
    with db.owner.begin() as session:
        op = OperationRow(
            id=uuid4(),
            idempotency_key="synthetic:old-deletion",
            outcome="succeeded",
            result={},
            created_at=datetime.now(UTC),
            completed_at=datetime.now(UTC),
        )
        session.add(op)
        session.flush()
        session.add(
            EvidenceTombstoneRow(
                evidence_id=source,
                deletion_operation_id=op.id,
                reason_category="owner_request",
                deleted_at=datetime.now(UTC),
                derived_summary={},
            )
        )
    assert MemoryService(db.sessions).build_context("violet").claims == []
    with pytest.raises(PermissionError, match="deleted"):
        MemoryService(db.sessions).materialize_claim(mixed.claim_id)


def test_legacy_or_inconsistent_archive_provenance_cannot_open_maintenance_gate(
    db: SimpleNamespace,
) -> None:
    with db.owner.begin() as session:
        op = OperationRow(
            id=uuid4(),
            idempotency_key="legacy",
            outcome="succeeded",
            result={},
            created_at=datetime.now(UTC),
            completed_at=datetime.now(UTC),
        )
        session.add(op)
        session.flush()
        session.add(
            EvidenceRow(
                id=uuid4(),
                source="hermes",
                source_conversation_id="telegram:legacy",
                captured_at=datetime.now(UTC),
                content={"contract_version": "2"},
                content_commitment="e" * 64,
                operation_id=op.id,
            )
        )
    with pytest.raises(ReadinessError, match="provenance review"):
        MaintenanceService(db.owner).prepare(
            storage_epoch=uuid4(),
            expected_commit=PIN,
            observed_commit=PIN,
            executors_stopped=True,
            journal=db.journal,
            key_store=db.keys,
        )
    with db.owner() as session:
        assert session.get(RuntimeAdmissionRow, True).state == "quarantined"


def test_sealed_metadata_detects_an_added_parent_even_with_operator_sql(
    db: SimpleNamespace,
) -> None:
    a = record(db, "a", "1")
    b = record(db, "b", "1")
    with db.owner.begin() as session:
        session.add(EvidenceDerivationRow(parent_id=a, child_id=b))
    with db.owner() as session, pytest.raises(PermissionError, match="coverage"):
        verify_archive_provenance(session)
    with pytest.raises(PermissionError, match="coverage"):
        deleter(db).delete("forged", delete_request(db, a, "forged"))
    with db.sessions() as session:
        for evidence_id in (a, b):
            payload = session.get(EvidencePayloadRow, evidence_id)
            assert payload is not None and db.keys.get(payload.key_ref) is not None


def test_partial_key_failure_never_reports_success_and_requires_controlled_recovery(
    db: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = record(db, "s", "1")
    record(db, "s", "1", "assistant")
    request = delete_request(db, source, "partial")
    original = db.keys.delete
    calls = 0

    def fail_second_delete(ref: UUID) -> bool:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("synthetic key-store interruption")
        return original(ref)

    monkeypatch.setattr(db.keys, "delete", fail_second_delete)
    with pytest.raises(OSError, match="synthetic key-store interruption"):
        deleter(db).delete("partial", request)
    with db.sessions() as session:
        assert session.scalar(select(func.count()).select_from(EvidenceTombstoneRow)) == 0
        assert session.scalar(select(func.count()).select_from(EvidencePayloadRow)) == 2
        assert (
            session.scalar(
                select(OperationRow.id).where(
                    OperationRow.idempotency_key == "partial",
                )
            )
            is None
        )
    assert db.journal.head().sequence == 1
    db.sessions.kw["bind"].dispose()
    with pytest.raises(DeletionJournalError, match="explicit recovery"):
        MaintenanceService(db.owner).prepare(
            storage_epoch=uuid4(),
            expected_commit=PIN,
            observed_commit=PIN,
            executors_stopped=True,
            key_store=db.keys,
            journal=db.journal,
            permit_verifier=db.verifier,
        )
    with db.owner() as session:
        assert session.get(RuntimeAdmissionRow, True).state == "quarantined"
    monkeypatch.setattr(db.keys, "delete", original)
    MaintenanceService(db.owner).prepare(
        storage_epoch=uuid4(),
        expected_commit=PIN,
        observed_commit=PIN,
        executors_stopped=True,
        key_store=db.keys,
        journal=db.journal,
        permit_verifier=db.verifier,
        recover_deletions=True,
    )
    with db.owner() as session:
        assert session.scalar(select(func.count()).select_from(EvidencePayloadRow)) == 0


@pytest.mark.parametrize("deletion_first", [True, False])
def test_reply_derivation_and_deletion_serialize_in_both_orders(
    db: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
    deletion_first: bool,
) -> None:
    source = record(db, "s", "1")
    request = delete_request(db, source, "race")
    entered = Event()
    release = Event()
    if deletion_first:
        original = db.keys.delete

        def held_delete(ref: UUID) -> bool:
            entered.set()
            assert release.wait(10)
            return original(ref)

        monkeypatch.setattr(db.keys, "delete", held_delete)
    else:
        original_encrypt = db.cipher.encrypt

        def held_encrypt(*args: Any) -> Any:
            entered.set()
            assert release.wait(10)
            return original_encrypt(*args)

        monkeypatch.setattr(db.cipher, "encrypt", held_encrypt)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = (
            pool.submit(deleter(db).delete, "race", request)
            if deletion_first
            else pool.submit(
                record,
                db,
                "s",
                "1",
                "assistant",
            )
        )
        try:
            assert entered.wait(5)
            second = (
                pool.submit(record, db, "s", "1", "assistant")
                if deletion_first
                else pool.submit(
                    deleter(db).delete,
                    "race",
                    request,
                )
            )
        finally:
            release.set()
        first.result(timeout=5)
        if deletion_first:
            with pytest.raises(PermissionError):
                second.result(timeout=5)
        else:
            assert second.result(timeout=5).derived_summary["evidence_records_deleted"] == 2
    with db.sessions() as session:
        assert session.scalar(select(func.count()).select_from(EvidencePayloadRow)) == 0
        with pytest.raises(PermissionError, match="deleted"):
            active_sources(session, {source})
