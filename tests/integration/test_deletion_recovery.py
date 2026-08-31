from __future__ import annotations

import json
import multiprocessing
import os
import subprocess
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event
from types import SimpleNamespace
from typing import Any
from uuid import UUID, uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, func, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker

import lucy.api as api
import lucy.authorization as authorization
import lucy.evidence as evidence_module
from lucy.approvals import ApprovalService
from lucy.archive import (
    ConversationArchiveService,
    ConversationMessageArchiveInput,
    TurnCaptureInput,
)
from lucy.archive_crypto import EnvelopeCipher, SqliteArchiveKeyStore
from lucy.authorization import (
    SensitiveActionPermitRequest,
    SensitiveActionPermitService,
    SensitiveActionPermitSigner,
    SensitiveActionPermitVerifier,
)
from lucy.contracts import ApprovalDecision, HumanActorType
from lucy.db.models import (
    AuditEventRow,
    Base,
    DeletionJournalBindingRow,
    DeletionJournalReceiptRow,
    EvidencePayloadRow,
    EvidenceTombstoneRow,
    MemoryClaimRow,
    OperationRow,
    RuntimeAdmissionRow,
)
from lucy.deletion_journal import DeletionJournalError, SqliteDeletionJournal
from lucy.evidence import EvidenceDeletionRequest, EvidenceService
from lucy.maintenance import MaintenanceService
from lucy.memory import MemoryService
from lucy.proposals import MemoryProposalInput, MemoryProposalService
from lucy.readiness import AdmittedSession, ServiceReadiness, admitted_session_factory

URL = os.getenv("LUCY_TEST_DATABASE_URL")
OWNER_URL = os.getenv("LUCY_TEST_OWNER_DATABASE_URL")
DOCKER = os.getenv("LUCY_TEST_DOCKER_BIN")
PIN = "fcbd1076a93841fa88855acce810e342a5b78101"
pytestmark = pytest.mark.skipif(not URL or not OWNER_URL, reason="isolated PostgreSQL required")


@pytest.fixture
def db(tmp_path: Path) -> Iterator[SimpleNamespace]:
    for value in (URL, OWNER_URL):
        parsed = make_url(value or "")
        assert (parsed.host, parsed.port, parsed.database) == ("127.0.0.1", 54329, "lucy_test")
    owner_engine = create_engine(OWNER_URL)
    owner = sessionmaker(owner_engine, expire_on_commit=False)
    keys_path, journal_path = tmp_path / "keys.sqlite", tmp_path / "journal.sqlite"
    keys = SqliteArchiveKeyStore(keys_path)
    journal = SqliteDeletionJournal.initialize(journal_path, registry_id=keys.registry_identity)
    head, epoch = journal.head(), uuid4()
    with owner.begin() as session:
        tables = ", ".join(f"lucy.{table.name}" for table in Base.metadata.sorted_tables)
        session.execute(text(f"TRUNCATE {tables} CASCADE"))
        session.execute(
            text(
                "INSERT INTO lucy.lifecycle VALUES (true,'ready',0,now()); "
                "INSERT INTO lucy.audit_head VALUES (true,0,repeat('0',64)); "
                "INSERT INTO lucy.budget_accounts VALUES ('model.daily',1000000,0,0)"
            )
        )
        session.add(
            RuntimeAdmissionRow(
                singleton=True, state="ready", storage_epoch=epoch, updated_at=datetime.now(UTC)
            )
        )
        session.add(
            DeletionJournalBindingRow(
                singleton=True, journal_id=head.journal_id, registry_id=head.registry_id
            )
        )
    sessions = admitted_session_factory(URL, epoch, journal)
    private = Ed25519PrivateKey.generate()
    verifier = SensitiveActionPermitVerifier(private.public_key())
    value = SimpleNamespace(
        owner=owner,
        sessions=sessions,
        epoch=epoch,
        journal=journal,
        keys=keys,
        keys_path=keys_path,
        journal_path=journal_path,
        verifier=verifier,
        private=private,
        archive=ConversationArchiveService(
            sessions,
            EnvelopeCipher(b"k" * 32, b"c" * 32, kek_version="synthetic-v1"),
            keys,
            capture_authorized=True,
        ),
    )
    yield value
    value.sessions.kw["bind"].dispose()
    sessions.kw["bind"].dispose()
    admitted_session_factory.cache_clear()
    owner_engine.dispose()


def source(db: SimpleNamespace, conversation: str = "s") -> UUID:
    db.archive.accept_turn(
        TurnCaptureInput(
            platform="telegram",
            source_conversation_id=conversation,
            source_turn_id="1",
        )
    )
    ids = []
    for role in ("user", "assistant"):
        result = db.archive.preserve_message(
            f"source:{conversation}:{role}",
            ConversationMessageArchiveInput(
                platform="telegram",
                source_conversation_id=conversation,
                source_turn_id="1",
                source_message_id=f"1:{role}",
                role=role,
                content="Synthetic violet compass",
            ),
        )
        ids.append(result.evidence_id)
    proposals = MemoryProposalService(db.sessions)
    proposal = proposals.submit(
        f"proposal:{conversation}",
        MemoryProposalInput(
            evidence_id=ids[1],
            subject="owner",
            predicate="likes",
            object="violet compass",
            confidence=0.9,
        ),
    )
    ApprovalService(db.sessions).decide(
        idempotency_key=f"approval:{conversation}",
        approval_id=proposal.approval_id,
        decision=ApprovalDecision.APPROVE,
        decided_by="synthetic-owner",
        actor_type=HumanActorType.OWNER,
    )
    applied = proposals.apply(proposal.proposal_id)
    MemoryService(db.sessions).materialize_claim(applied.claim_id)
    return ids[0]


def request(db: SimpleNamespace, evidence_id: UUID) -> EvidenceDeletionRequest:
    permit = SensitiveActionPermitService(
        db.sessions,
        SensitiveActionPermitSigner(db.private),
    ).issue(
        f"permit:delete:{evidence_id}",
        SensitiveActionPermitRequest(
            action="evidence.delete",
            evidence_ids=(evidence_id,),
            reason="owner_request",
            owner_subject="synthetic-owner",
            owner_interaction_id="synthetic-owner-event",
        ),
    )
    return EvidenceDeletionRequest(evidence_id=evidence_id, reason="owner_request", permit=permit)


def delete(db: SimpleNamespace, candidate: EvidenceDeletionRequest) -> Any:
    return EvidenceService(db.sessions, None, db.keys, db.verifier, journal=db.journal).delete(
        "delete",
        candidate,
    )


def recover(db: SimpleNamespace, **overrides: Any) -> None:
    db.sessions.kw["bind"].dispose()
    epoch = uuid4()
    options = dict(
        key_store=db.keys, journal=db.journal, permit_verifier=db.verifier, recover_deletions=True
    )
    options.update(overrides)
    MaintenanceService(db.owner).prepare(
        storage_epoch=epoch,
        expected_commit=PIN,
        observed_commit=PIN,
        executors_stopped=True,
        **options,
    )
    db.epoch = epoch
    db.sessions = admitted_session_factory(URL, epoch, db.journal)


def assert_fenced(db: SimpleNamespace) -> None:
    with pytest.raises(DeletionJournalError, match="fenced"):
        MemoryService(db.sessions).build_context("violet")
    with pytest.raises(DeletionJournalError, match="fenced"):
        ServiceReadiness(
            db.owner, mode="all-local", storage_epoch=db.epoch, journal=db.journal
        ).check()


@pytest.mark.parametrize(
    "boundary", ["before_append", "ambiguous_append", "first_key", "before_commit"]
)
def test_failure_boundaries_preserve_intent_and_fence_until_recovered(
    db: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    candidate = request(db, source(db))
    append, remove = db.journal.append, db.keys.delete

    def failed_append(*args: Any) -> Any:
        if boundary == "ambiguous_append":
            append(*args)
        raise OSError("synthetic append interruption")

    def failed_delete(ref: UUID) -> bool:
        remove(ref)
        raise OSError("synthetic key interruption")

    def failed_commit(session: Any) -> None:
        if session.info.get("deletion_execution"):
            raise OSError("synthetic commit interruption")

    with monkeypatch.context() as patch:
        if "append" in boundary:
            patch.setattr(db.journal, "append", failed_append)
        if boundary == "first_key":
            patch.setattr(db.keys, "delete", failed_delete)
        if boundary == "before_commit":
            event.listen(AdmittedSession, "before_commit", failed_commit)
        try:
            with pytest.raises(OSError, match="synthetic"):
                delete(db, candidate)
        finally:
            if boundary == "before_commit":
                event.remove(AdmittedSession, "before_commit", failed_commit)
    with db.owner() as session:
        assert session.scalar(select(func.count()).select_from(DeletionJournalReceiptRow)) == 0
        assert session.scalar(select(func.count()).select_from(EvidencePayloadRow)) == 2
        assert session.scalar(select(MemoryClaimRow.object)) == "violet compass"
    if boundary == "before_append":
        assert db.journal.head().sequence == 0
        assert MemoryService(db.sessions).build_context("violet").claims
        return
    assert db.journal.head().sequence == 1
    assert_fenced(db)
    with pytest.raises(DeletionJournalError, match="explicit recovery"):
        recover(db, recover_deletions=False)
    recover(db)
    assert MemoryService(db.sessions).build_context("violet").claims == []
    with db.owner() as session:
        assert session.scalar(select(func.count()).select_from(EvidencePayloadRow)) == 0
        assert session.scalar(select(func.count()).select_from(EvidenceTombstoneRow)) == 2
        assert session.scalar(select(func.count()).select_from(DeletionJournalReceiptRow)) == 1
        assert (
            session.scalar(
                select(func.count())
                .select_from(AuditEventRow)
                .where(
                    AuditEventRow.event_type == "evidence.deleted",
                )
            )
            == 1
        )


def test_lost_commit_response_replays_durable_result_without_repeating_keys(
    db: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = request(db, source(db))

    def lose_response(session: Any) -> None:
        if session.info.get("deletion_execution"):
            raise OSError("synthetic response lost after commit")

    event.listen(AdmittedSession, "after_commit", lose_response)
    try:
        with pytest.raises(OSError, match="after commit"):
            delete(db, candidate)
    finally:
        event.remove(AdmittedSession, "after_commit", lose_response)
    monkeypatch.setattr(db.keys, "delete", lambda _: pytest.fail("must not repeat key deletion"))
    assert delete(db, candidate).replayed
    assert db.journal.head().sequence == 1
    assert MemoryService(db.sessions).build_context("violet").claims == []


def test_expired_permit_recovers_only_previously_accepted_authority(
    db: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = source(db)
    past = datetime.now(UTC) - timedelta(minutes=10)

    class OldClock(datetime):
        @classmethod
        def now(cls, tz: Any = None) -> datetime:
            return past

    with monkeypatch.context() as patch:
        patch.setattr(authorization, "datetime", OldClock)
        patch.setattr(evidence_module, "datetime", OldClock)
        candidate = request(db, root)
        patch.setattr(
            db.keys, "delete", lambda _: (_ for _ in ()).throw(OSError("synthetic crash"))
        )
        with pytest.raises(OSError):
            delete(db, candidate)
    assert db.journal.entry(1).intent.permit.expires_at < datetime.now(UTC)
    recover(db)
    assert MemoryService(db.sessions).build_context("violet").claims == []


def test_wrong_registry_cannot_start_or_recover_deletion(
    db: SimpleNamespace, tmp_path: Path
) -> None:
    candidate = request(db, source(db))
    wrong = SqliteArchiveKeyStore(tmp_path / "wrong.sqlite")
    with pytest.raises(DeletionJournalError, match="registry identity"):
        EvidenceService(db.sessions, None, wrong, db.verifier, journal=db.journal).delete(
            "delete", candidate
        )
    assert db.journal.head().sequence == 0
    with pytest.raises(DeletionJournalError, match="identity-bound"):
        recover(db, key_store=wrong)
    with db.owner() as session:
        assert session.get(RuntimeAdmissionRow, True).state == "quarantined"


def test_external_journal_rollback_is_not_silently_adopted(db: SimpleNamespace) -> None:
    candidate = request(db, source(db))
    old_journal = db.journal_path.read_bytes()
    assert delete(db, candidate).deleted
    # Deliberately restore only this fixture's synthetic external journal.
    db.journal_path.write_bytes(old_journal)
    assert_fenced(db)
    with pytest.raises(DeletionJournalError, match="rolled back"):
        recover(db)


def test_recovery_applies_only_unacknowledged_suffix(
    db: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = request(db, source(db))
    second = request(db, source(db, "independent"))
    assert delete(db, first).deleted
    original = db.keys.delete
    with monkeypatch.context() as patch:
        patch.setattr(
            db.keys, "delete", lambda _: (_ for _ in ()).throw(OSError("synthetic crash"))
        )
        with pytest.raises(OSError):
            EvidenceService(db.sessions, None, db.keys, db.verifier, journal=db.journal).delete(
                "delete:second",
                second,
            )
    first_refs = {target.key_ref for target in db.journal.entry(1).intent.targets}

    def only_second(ref: UUID) -> bool:
        assert ref not in first_refs, "must not repeat an acknowledged deletion"
        return original(ref)

    monkeypatch.setattr(db.keys, "delete", only_second)
    assert db.journal.head().sequence == 2
    assert_fenced(db)
    recover(db)
    with db.owner() as session:
        assert session.scalar(select(func.count()).select_from(DeletionJournalReceiptRow)) == 2
        assert session.scalar(select(func.count()).select_from(EvidenceTombstoneRow)) == 4


def test_journal_outage_returns_content_free_503_without_projection_access(
    db: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source(db)
    monkeypatch.setenv("LUCY_SERVICE_MODE", "routine")
    monkeypatch.setenv("LUCY_ADAPTER_TOKEN", "synthetic-token")
    monkeypatch.setattr(api, "_ready_sessions", lambda: db.sessions)
    monkeypatch.setattr(
        db.journal,
        "head",
        lambda: (_ for _ in ()).throw(
            DeletionJournalError("deletion journal unavailable"),
        ),
    )
    with TestClient(api.app) as client:
        response = client.post(
            "/v1/memory/lookup",
            json={"query": "violet"},
            headers={"Authorization": "Bearer synthetic-token"},
        )
    assert response.status_code == 503
    assert response.json() == {"detail": "Lucy storage is not admitted"}


def test_deletion_waits_for_reader_then_queued_reader_rechecks_pending_intent(
    db: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = request(db, source(db))
    held, release_reader, appended, release_deleter = Event(), Event(), Event(), Event()
    original = db.journal.append

    def reader() -> None:
        with db.sessions.begin() as session:
            assert session.scalar(select(MemoryClaimRow.object)) == "violet compass"
            held.set()
            assert release_reader.wait(10)

    def append_and_pause(*args: Any) -> Any:
        original(*args)
        appended.set()
        assert release_deleter.wait(10)
        raise OSError("synthetic interruption")

    monkeypatch.setattr(db.journal, "append", append_and_pause)
    with ThreadPoolExecutor(max_workers=3) as executor:
        first = executor.submit(reader)
        assert held.wait(5)
        deleting = executor.submit(delete, db, candidate)
        try:
            assert not appended.wait(0.1)
            release_reader.set()
            first.result(timeout=5)
            assert appended.wait(5)
            queued = executor.submit(MemoryService(db.sessions).build_context, "violet")
            release_deleter.set()
            with pytest.raises(OSError):
                deleting.result(timeout=5)
            with pytest.raises(DeletionJournalError, match="fenced"):
                queued.result(timeout=5)
        finally:
            release_reader.set()
            release_deleter.set()


def _killed_deleter(
    url: str,
    epoch: UUID,
    journal_path: Path,
    journal_id: UUID,
    registry_id: UUID,
    keys_path: Path,
    public_key: bytes,
    candidate: str,
    reached: Any,
    release: Any,
) -> None:
    journal = SqliteDeletionJournal(journal_path, journal_id=journal_id, registry_id=registry_id)
    keys = SqliteArchiveKeyStore(keys_path)
    original = keys.delete

    def delete_and_pause(ref: UUID) -> bool:
        result = original(ref)
        reached.set()
        release.wait(30)
        return result

    keys.delete = delete_and_pause
    EvidenceService(
        admitted_session_factory(url, epoch, journal),
        None,
        keys,
        SensitiveActionPermitVerifier(Ed25519PublicKey.from_public_bytes(public_key)),
        journal=journal,
    ).delete("delete", EvidenceDeletionRequest.model_validate_json(candidate))


def test_os_process_kill_after_external_key_commit_recovers_with_fresh_providers(
    db: SimpleNamespace,
) -> None:
    candidate = request(db, source(db))
    ctx = multiprocessing.get_context("spawn")
    reached, release = ctx.Event(), ctx.Event()
    head = db.journal.head()
    process = ctx.Process(
        target=_killed_deleter,
        args=(
            URL,
            db.epoch,
            db.journal_path,
            head.journal_id,
            head.registry_id,
            db.keys_path,
            db.private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
            candidate.model_dump_json(),
            reached,
            release,
        ),
    )
    process.start()
    try:
        assert reached.wait(15), "child did not commit an external key deletion"
        process.kill()
        process.join(timeout=5)
        assert not process.is_alive() and process.exitcode != 0
    finally:
        if process.is_alive():
            process.kill()
            process.join(timeout=5)
        process.close()
    assert_fenced(db)
    db.journal = SqliteDeletionJournal(
        db.journal_path, journal_id=head.journal_id, registry_id=head.registry_id
    )
    db.keys = SqliteArchiveKeyStore(db.keys_path)
    recover(db)
    assert MemoryService(db.sessions).build_context("violet").claims == []
    recover(db)  # A second explicit prepare must not repeat the logical deletion.
    with db.owner() as session:
        assert session.scalar(select(func.count()).select_from(DeletionJournalReceiptRow)) == 1
        assert (
            session.scalar(
                select(func.count())
                .select_from(OperationRow)
                .where(
                    OperationRow.idempotency_key == "delete",
                )
            )
            == 1
        )


@pytest.mark.skipif(not DOCKER, reason="explicit isolated Docker backup test required")
def test_restored_pre_deletion_backup_cannot_resurrect_projection_or_permit_authority(
    db: SimpleNamespace,
) -> None:
    root = source(db)
    inspected = subprocess.run(
        [
            DOCKER,
            "inspect",
            "--format",
            "{{json .Config.Labels}}",
            "cloud-lucy-retention-tests-postgres-1",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    labels = json.loads(inspected.stdout)
    assert labels["com.docker.compose.project"] == "cloud-lucy-retention-tests"
    assert labels["com.docker.compose.service"] == "postgres"
    command = [DOCKER, "exec", "-i", "cloud-lucy-retention-tests-postgres-1"]
    backup = subprocess.run(
        [*command, "pg_dump", "-U", "lucy_owner", "-d", "lucy_test", "--format=custom"],
        check=True,
        capture_output=True,
        timeout=30,
    ).stdout
    # Permit did not exist in the backup. The independent accepted intent is the
    # authority to finish after restore, not a resurrected database permit row.
    candidate = request(db, root)
    assert delete(db, candidate).deleted
    db.sessions.kw["bind"].dispose()
    subprocess.run(
        [
            *command,
            "pg_restore",
            "-U",
            "lucy_owner",
            "--dbname=lucy_test",
            "--clean",
            "--if-exists",
            "--no-owner",
            "--exit-on-error",
        ],
        input=backup,
        check=True,
        capture_output=True,
        timeout=30,
    )
    with db.owner() as session:
        assert session.get(RuntimeAdmissionRow, True).state == "ready"
        assert session.scalar(select(MemoryClaimRow.object)) == "violet compass"
        assert session.scalar(select(func.count()).select_from(DeletionJournalReceiptRow)) == 0
    assert_fenced(db)  # Old ready flag AND matching old epoch do not open admission.
    recover(db)
    assert MemoryService(db.sessions).build_context("violet").claims == []
    with db.owner() as session:
        assert session.scalar(select(func.count()).select_from(EvidencePayloadRow)) == 0
        assert session.scalar(select(func.count()).select_from(DeletionJournalReceiptRow)) == 1
