from __future__ import annotations

import os
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from threading import Event
from time import monotonic
from typing import Any
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import sessionmaker

import lucy.api as api
from lucy.archive import (
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
from lucy.db.models import (
    Base,
    DeletionJournalBindingRow,
    EvidencePayloadRow,
    LifecycleRow,
    OperationRow,
    RuntimeAdmissionRow,
    StartupRunRow,
)
from lucy.deletion_journal import SqliteDeletionJournal
from lucy.evidence import EvidenceDeletionRequest, EvidenceRetrievalRequest, EvidenceService
from lucy.maintenance import MaintenanceService
from lucy.memory import MemoryService
from lucy.model_execution import MODEL, ModelExecutionBegin, ModelExecutionService
from lucy.proposals import GatewayMemoryProposalInput, MemoryProposalService
from lucy.readiness import (
    ADMISSION_LOCK,
    SERVICE_ROLES,
    ReadinessError,
    ServiceReadiness,
    admitted_session_factory,
)
from lucy.rejoining import RejoiningService

ROOT = Path(__file__).parents[2]
ADMIN_URL = os.getenv("LUCY_TEST_ROLES_ADMIN_DATABASE_URL")
PIN = "fcbd1076a93841fa88855acce810e342a5b78101"
pytestmark = pytest.mark.skipif(not ADMIN_URL, reason="requires isolated production-role database")


@pytest.fixture(scope="module")
def role_urls() -> Iterator[dict[str, str]]:
    assert ADMIN_URL is not None
    parsed = make_url(ADMIN_URL)
    assert (parsed.database, parsed.host, parsed.port) == (
        "lucy_roles_test",
        "127.0.0.1",
        54330,
    ), "refusing to bootstrap outside the isolated role-test cluster"
    admin = create_engine(ADMIN_URL)
    with admin.begin() as connection:
        assert connection.scalar(text("SELECT current_database()")) == "lucy_roles_test"
        if not connection.scalar(text("SELECT 1 FROM pg_roles WHERE rolname='lucy_app'")):
            connection.exec_driver_sql(
                (ROOT / "deploy/postgres/production_bootstrap.sql.example").read_text(),
            )
        assert (
            connection.scalar(text("SELECT rolcanlogin FROM pg_roles WHERE rolname='lucy_app'"))
            is False
        )
    owner_url = parsed.set(
        username="lucy_migrator", password="synthetic-migrator-only"
    ).render_as_string(hide_password=False)
    # Migrate as a NON-superuser database/schema owner, not the bootstrap admin.
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("LUCY_MIGRATION_DATABASE_URL", owner_url)
        config = Config(str(ROOT / "alembic.ini"))
        config.set_main_option("script_location", str(ROOT / "migrations"))
        command.upgrade(config, "head")
    owner = create_engine(owner_url)
    with owner.begin() as connection:
        connection.execute(
            text((ROOT / "deploy/postgres/production_roles.sql.example").read_text())
        )
    urls = {"owner": owner_url, "admin": ADMIN_URL}
    with admin.begin() as connection:
        for mode, capability in SERVICE_ROLES.items():
            login = f"test_{mode}"
            if not connection.scalar(
                text("SELECT 1 FROM pg_roles WHERE rolname=:login"), {"login": login}
            ):
                connection.exec_driver_sql(
                    f"CREATE ROLE {login} LOGIN PASSWORD 'synthetic-service-only' "
                    "NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS",
                )
            connection.exec_driver_sql(f"GRANT {capability} TO {login}")
            urls[mode] = parsed.set(
                username=login, password="synthetic-service-only"
            ).render_as_string(hide_password=False)
    owner.dispose()
    admin.dispose()
    yield urls
    admitted_session_factory.cache_clear()


@pytest.fixture
def role_db(role_urls: dict[str, str]) -> Iterator[dict[str, Any]]:
    owner_engine = create_engine(role_urls["owner"])
    owner = sessionmaker(owner_engine, expire_on_commit=False)
    with owner_engine.begin() as connection:
        tables = ", ".join(f"lucy.{table.name}" for table in Base.metadata.sorted_tables)
        connection.execute(text(f"TRUNCATE {tables} CASCADE"))
        connection.execute(
            text(
                "INSERT INTO lucy.lifecycle VALUES (true, 'offline', 0, now()); "
                "INSERT INTO lucy.runtime_admission VALUES (true, 'quarantined', NULL, now()); "
                "INSERT INTO lucy.audit_head VALUES (true, 0, repeat('0',64)); "
                "INSERT INTO lucy.budget_accounts VALUES ('model.daily',1000000,0,0),"
                "('action.daily',1000000,0,0)"
            )
        )
    epoch = uuid4()
    MaintenanceService(owner).prepare(
        storage_epoch=epoch, expected_commit=PIN, observed_commit=PIN, executors_stopped=True
    )
    engines = {mode: create_engine(role_urls[mode]) for mode in SERVICE_ROLES}
    sessions = {
        mode: sessionmaker(engine, expire_on_commit=False) for mode, engine in engines.items()
    }
    yield {"owner": owner, "epoch": epoch, "sessions": sessions, "urls": role_urls}
    for mode, engine in engines.items():
        engine.dispose()
        admitted_session_factory(role_urls[mode], epoch).kw["bind"].dispose()
    admitted_session_factory.cache_clear()
    owner_engine.dispose()


@pytest.mark.parametrize("mode", SERVICE_ROLES)
def test_separate_login_starts_read_only_without_recovering_live_work(
    role_db: dict[str, Any],
    mode: str,
) -> None:
    routine = role_db["sessions"]["routine"]
    begun = ModelExecutionService(routine).begin(
        ModelExecutionBegin(
            idempotency_key="hermes-model:synthetic-session:synthetic-request",
            model=MODEL,
            reservation_microusd=5000,
            session_id="synthetic-session",
            api_request_id="synthetic-request",
        )
    )
    with role_db["owner"]() as session:
        before_startups = session.scalar(select(func.count()).select_from(StartupRunRow))
        before_pending = session.scalar(
            select(func.count())
            .select_from(OperationRow)
            .where(
                OperationRow.outcome == "pending",
            )
        )
    for _ in range(2):
        ServiceReadiness(
            role_db["sessions"][mode], mode=mode, storage_epoch=role_db["epoch"]
        ).check()
    with role_db["owner"]() as session:
        assert session.scalar(select(func.count()).select_from(StartupRunRow)) == before_startups
        assert (
            session.scalar(
                select(func.count())
                .select_from(OperationRow)
                .where(
                    OperationRow.outcome == "pending",
                )
            )
            == before_pending
            == 1
        )
    assert begun.status == "executing"


@pytest.mark.parametrize("mode", SERVICE_ROLES)
@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE lucy.runtime_admission SET state='ready'",
        "UPDATE lucy.lifecycle SET state='ready'",
        "UPDATE lucy.evidence SET source='synthetic'",
        "UPDATE lucy.audit_events SET event_type='forged'",
        "UPDATE lucy.capture_receipts SET capture_enabled=true",
        "UPDATE lucy.deletion_journal_binding SET journal_id=gen_random_uuid()",
        "DELETE FROM lucy.deletion_journal_receipts",
        "INSERT INTO lucy.startup_runs (id) VALUES (gen_random_uuid())",
        "CREATE TABLE lucy.forbidden_table (id integer)",
        "CREATE TABLE public.forbidden_table (id integer)",
        "CREATE ROLE forbidden_role",
    ],
)
def test_each_service_login_is_denied_control_and_administrative_writes(
    role_db: dict[str, Any],
    mode: str,
    statement: str,
) -> None:
    with pytest.raises(DBAPIError) as caught, role_db["sessions"][mode].begin() as session:
        session.execute(text(statement))
    assert caught.value.orig.sqlstate == "42501"  # permission denied, not a syntax/constraint error


@pytest.mark.parametrize("mode", ["routine", "policy", "evidence"])
def test_only_deleter_can_acknowledge_independent_intents(
    role_db: dict[str, Any], mode: str
) -> None:
    with pytest.raises(DBAPIError) as caught, role_db["sessions"][mode].begin() as session:
        session.execute(
            text(
                "INSERT INTO lucy.deletion_journal_receipts VALUES "
                "(1,gen_random_uuid(),repeat('0',64),gen_random_uuid())"
            )
        )
    assert caught.value.orig.sqlstate == "42501"


@pytest.mark.parametrize("mode", ["routine", "policy"])
def test_routine_and_policy_cannot_read_ciphertext(role_db: dict[str, Any], mode: str) -> None:
    with pytest.raises(DBAPIError) as caught, role_db["sessions"][mode]() as session:
        session.execute(select(EvidencePayloadRow))
    assert caught.value.orig.sqlstate == "42501"


@pytest.mark.parametrize("mode", ["evidence", "deletion"])
@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE lucy.sensitive_action_permits SET serialized_permit='{}'::jsonb",
        "INSERT INTO lucy.sensitive_action_permits (id) VALUES (gen_random_uuid())",
        "UPDATE lucy.evidence_tombstones SET reason_category='owner_request'",
    ],
)
def test_read_and_deletion_services_cannot_mint_authority_or_rewrite_deletion_history(
    role_db: dict[str, Any],
    mode: str,
    statement: str,
) -> None:
    with pytest.raises(DBAPIError) as caught, role_db["sessions"][mode].begin() as session:
        session.execute(text(statement))
    assert caught.value.orig.sqlstate == "42501"


def test_actual_four_role_archive_permit_read_and_delete_path(
    role_db: dict[str, Any],
    tmp_path: Path,
) -> None:
    sessions = role_db["sessions"]
    epoch = role_db["epoch"]
    for mode in SERVICE_ROLES:
        ServiceReadiness(sessions[mode], mode=mode, storage_epoch=epoch).check()
    cipher = EnvelopeCipher(b"k" * 32, b"c" * 32, kek_version="synthetic-v1")
    keys = MemoryArchiveKeyStore()
    journal = SqliteDeletionJournal.initialize(
        tmp_path / "journal.sqlite", registry_id=keys.registry_identity
    )
    head = journal.head()
    with role_db["owner"].begin() as session:
        session.add(
            DeletionJournalBindingRow(
                singleton=True,
                journal_id=head.journal_id,
                registry_id=head.registry_id,
            )
        )
    admitted = {
        mode: admitted_session_factory(role_db["urls"][mode], epoch, journal)
        for mode in SERVICE_ROLES
    }
    archive = ConversationArchiveService(admitted["routine"], cipher, keys, capture_authorized=True)
    archive.accept_turn(
        TurnCaptureInput(platform="telegram", source_conversation_id="s", source_turn_id="t")
    )
    archived = archive.preserve_message(
        "source:roles",
        ConversationMessageArchiveInput(
            platform="telegram",
            source_conversation_id="s",
            source_turn_id="t",
            source_message_id="t:user",
            role="user",
            content="Synthetic tea preference",
        ),
    )
    reply = archive.preserve_message(
        "source:roles:reply",
        ConversationMessageArchiveInput(
            platform="telegram",
            source_conversation_id="s",
            source_turn_id="t",
            source_message_id="t:assistant",
            role="assistant",
            content="Synthetic derived tea reply",
        ),
    )
    proposal = MemoryProposalService(admitted["routine"]).submit(
        f"hermes-memory-proposal:{uuid4()}",
        GatewayMemoryProposalInput(
            evidence_id=reply.evidence_id,
            source_conversation_id="s",
            source_turn_id="t",
            subject="owner",
            predicate="likes",
            object="tea",
            confidence=0.9,
        ),
    )
    assert proposal.status == "pending"
    assert MemoryService(admitted["routine"]).build_context("tea").claims == []
    private = Ed25519PrivateKey.generate()
    issuer = SensitiveActionPermitService(admitted["policy"], SensitiveActionPermitSigner(private))
    verifier = SensitiveActionPermitVerifier(private.public_key())
    read_permit = issuer.issue(
        "permit:read",
        SensitiveActionPermitRequest(
            action=SensitiveAction.EVIDENCE_RETRIEVE,
            owner_subject="owner:synthetic",
            owner_interaction_id="synthetic:read",
            evidence_ids=(archived.evidence_id,),
            reason="owner_review",
        ),
    )
    result = EvidenceService(admitted["evidence"], cipher, keys, verifier).retrieve(
        "read:roles",
        EvidenceRetrievalRequest(
            evidence_id=archived.evidence_id, reason="owner_review", permit=read_permit
        ),
        owner=True,
    )
    assert result.message.content == "Synthetic tea preference"
    delete_permit = issuer.issue(
        "permit:delete",
        SensitiveActionPermitRequest(
            action=SensitiveAction.EVIDENCE_DELETE,
            owner_subject="owner:synthetic",
            owner_interaction_id="synthetic:delete",
            evidence_ids=(archived.evidence_id,),
            reason="owner_request",
        ),
    )
    deleted = EvidenceService(admitted["deletion"], None, keys, verifier, journal=journal).delete(
        "delete:roles",
        EvidenceDeletionRequest(
            evidence_id=archived.evidence_id, reason="owner_request", permit=delete_permit
        ),
    )
    assert deleted.deleted and deleted.derived_summary["proposals_rejected"] == 1
    assert deleted.derived_summary["evidence_records_deleted"] == 2
    for factory in admitted.values():
        factory.kw["bind"].dispose()


@pytest.mark.parametrize("mode", SERVICE_ROLES)
@pytest.mark.parametrize(
    "table",
    [
        "evidence_derivations",
        "claim_sources",
        "proposal_sources",
        "correction_sources",
    ],
)
def test_each_identity_cannot_erase_provenance_links(
    role_db: dict[str, Any],
    mode: str,
    table: str,
) -> None:
    with pytest.raises(DBAPIError) as caught, role_db["sessions"][mode].begin() as session:
        session.execute(text(f"DELETE FROM lucy.{table}"))
    assert caught.value.orig.sqlstate == "42501"


@pytest.mark.parametrize("mode", ["policy", "evidence", "deletion"])
def test_nonwriter_identities_cannot_expand_a_deletion_closure(
    role_db: dict[str, Any],
    mode: str,
) -> None:
    with pytest.raises(DBAPIError) as caught, role_db["sessions"][mode].begin() as session:
        session.execute(
            text(
                "INSERT INTO lucy.evidence_derivations VALUES (gen_random_uuid(),gen_random_uuid())"
            )
        )
    assert caught.value.orig.sqlstate == "42501"


@pytest.mark.parametrize("mode", SERVICE_ROLES)
def test_quarantine_and_wrong_external_epoch_block_every_identity(
    role_db: dict[str, Any],
    mode: str,
) -> None:
    with pytest.raises(ReadinessError, match="epoch mismatch"):
        ServiceReadiness(role_db["sessions"][mode], mode=mode, storage_epoch=uuid4()).check()
    MaintenanceService(role_db["owner"]).quarantine()
    with pytest.raises(ReadinessError, match="quarantined"):
        ServiceReadiness(
            role_db["sessions"][mode], mode=mode, storage_epoch=role_db["epoch"]
        ).check()
    with (
        pytest.raises(ReadinessError, match="quarantined"),
        admitted_session_factory(role_db["urls"][mode], role_db["epoch"])() as session,
    ):
        session.execute(text("SELECT 1"))


def test_maintenance_refuses_connected_service_and_keeps_storage_closed(
    role_db: dict[str, Any],
) -> None:
    with role_db["sessions"]["routine"]() as routine:
        routine.execute(text("SELECT 1"))
        with pytest.raises(ReadinessError, match="still connected"):
            MaintenanceService(role_db["owner"]).prepare(
                storage_epoch=uuid4(),
                expected_commit=PIN,
                observed_commit=PIN,
                executors_stopped=True,
            )
    with role_db["owner"]() as session:
        assert session.get(RuntimeAdmissionRow, True).state == "quarantined"


def test_maintenance_never_silently_recovers_pending_external_work(role_db: dict[str, Any]) -> None:
    with role_db["owner"].begin() as session:
        session.add(
            OperationRow(
                id=uuid4(),
                idempotency_key="synthetic:inflight",
                outcome="pending",
                result=None,
                created_at=datetime.now(UTC),
                completed_at=None,
            )
        )
    with pytest.raises(ReadinessError, match="explicit ambiguous-recovery"):
        MaintenanceService(role_db["owner"]).prepare(
            storage_epoch=uuid4(),
            expected_commit=PIN,
            observed_commit=PIN,
            executors_stopped=True,
        )
    with role_db["owner"]() as session:
        assert (
            session.scalar(
                select(OperationRow.outcome).where(
                    OperationRow.idempotency_key == "synthetic:inflight",
                )
            )
            == "pending"
        )


def test_quarantine_blocks_previously_constructed_session_factory(role_db: dict[str, Any]) -> None:
    sessions = admitted_session_factory(role_db["urls"]["routine"], role_db["epoch"])
    with sessions() as session:
        assert session.scalar(text("SELECT 1")) == 1
    MaintenanceService(role_db["owner"]).quarantine()
    with pytest.raises(ReadinessError, match="quarantined"), sessions() as session:
        session.execute(text("SELECT 1"))


@pytest.mark.parametrize(
    ("grant", "revoke", "diagnostic"),
    [
        (
            "GRANT SELECT (ciphertext) ON lucy.evidence_payloads TO test_routine",
            "REVOKE SELECT (ciphertext) ON lucy.evidence_payloads FROM test_routine",
            "exceeds its reviewed capabilities",
        ),
        (
            "GRANT lucy_policy TO test_routine",
            "REVOKE lucy_policy FROM test_routine",
            "compound capability",
        ),
    ],
)
def test_accidental_extra_capabilities_reject_service_startup(
    role_db: dict[str, Any],
    grant: str,
    revoke: str,
    diagnostic: str,
) -> None:
    admin = create_engine(role_db["urls"]["admin"])
    try:
        with admin.begin() as connection:
            connection.execute(text(grant))
        with pytest.raises(ReadinessError, match=diagnostic):
            ServiceReadiness(
                role_db["sessions"]["routine"],
                mode="routine",
                storage_epoch=role_db["epoch"],
            ).check()
    finally:
        with admin.begin() as connection:
            connection.execute(text(revoke))
        admin.dispose()


def test_quarantine_waits_for_admitted_transaction_then_blocks_new_work(
    role_db: dict[str, Any],
) -> None:
    admitted = admitted_session_factory(role_db["urls"]["routine"], role_db["epoch"])
    release = Event()
    active = Event()

    def hold_transaction() -> None:
        with admitted.begin() as session:
            assert session.scalar(text("SHOW transaction_isolation")) == "read committed"
            active.set()
            assert release.wait(15), "test did not release admitted transaction"

    with ThreadPoolExecutor(max_workers=2) as pool:
        held = pool.submit(hold_transaction)
        try:
            assert active.wait(5)
            closing = pool.submit(MaintenanceService(role_db["owner"]).quarantine)
            # Observe the actual lock wait, rather than assuming a scheduling delay.
            deadline = monotonic() + 5
            waiting = False
            while monotonic() < deadline:
                with role_db["owner"]() as session:
                    waiting = bool(
                        session.scalar(
                            text(
                                "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype='advisory' "
                                "AND classid=:hi AND objid=:lo "
                                "AND mode='ExclusiveLock' AND NOT granted)"
                            ),
                            {"hi": ADMISSION_LOCK >> 32, "lo": ADMISSION_LOCK & 0xFFFFFFFF},
                        )
                    )
                if waiting:
                    break
                release.wait(0.02)
            assert waiting and not closing.done()
        finally:
            release.set()
        held.result(timeout=5)
        closing.result(timeout=5)
    with pytest.raises(ReadinessError, match="quarantined"), admitted() as session:
        session.execute(text("SELECT 1"))


def test_failed_recovery_leaves_durably_closed_gate(
    role_db: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def crash(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("synthetic recovery interruption")

    monkeypatch.setattr(RejoiningService, "run", crash)
    with pytest.raises(RuntimeError, match="synthetic recovery interruption"):
        MaintenanceService(role_db["owner"]).prepare(
            storage_epoch=uuid4(),
            expected_commit=PIN,
            observed_commit=PIN,
            executors_stopped=True,
        )
    # Read using a fresh connection: not just the failed transaction's identity map.
    fresh = create_engine(role_db["urls"]["owner"])
    try:
        with fresh.connect() as connection:
            assert (
                connection.scalar(text("SELECT state FROM lucy.runtime_admission")) == "quarantined"
            )
    finally:
        fresh.dispose()


def _archive_fixture(role_db: dict[str, Any]) -> tuple[Any, MemoryArchiveKeyStore]:
    keys = MemoryArchiveKeyStore()
    archive = ConversationArchiveService(
        role_db["owner"],
        EnvelopeCipher(b"k" * 32, b"c" * 32, kek_version="synthetic-v1"),
        keys,
        capture_authorized=True,
    )
    archive.accept_turn(
        TurnCaptureInput(platform="telegram", source_conversation_id="s", source_turn_id="t"),
    )
    archived = archive.preserve_message(
        "source:restore",
        ConversationMessageArchiveInput(
            platform="telegram",
            source_conversation_id="s",
            source_turn_id="t",
            source_message_id="t:user",
            role="user",
            content="Synthetic restore evidence",
        ),
    )
    return archived, keys


@pytest.mark.parametrize("missing_registry", [True, False])
def test_missing_or_empty_registry_never_admits_or_deletes_restored_evidence(
    role_db: dict[str, Any],
    missing_registry: bool,
) -> None:
    archived, _keys = _archive_fixture(role_db)
    with pytest.raises(ReadinessError, match="registry"):
        MaintenanceService(role_db["owner"]).prepare(
            storage_epoch=uuid4(),
            expected_commit=PIN,
            observed_commit=PIN,
            executors_stopped=True,
            key_store=None if missing_registry else MemoryArchiveKeyStore(),
        )
    with role_db["owner"]() as session:
        assert session.get(RuntimeAdmissionRow, True).state == "quarantined"
        assert session.get(EvidencePayloadRow, archived.evidence_id) is not None


def test_successful_controlled_recovery_rotates_epoch_and_rejects_stale_clients(
    role_db: dict[str, Any],
) -> None:
    _archived, keys = _archive_fixture(role_db)
    old = admitted_session_factory(role_db["urls"]["routine"], role_db["epoch"])
    new_epoch = uuid4()
    MaintenanceService(role_db["owner"]).prepare(
        storage_epoch=new_epoch,
        expected_commit=PIN,
        observed_commit=PIN,
        executors_stopped=True,
        key_store=keys,
    )
    with pytest.raises(ReadinessError, match="epoch mismatch"), old() as session:
        session.execute(text("SELECT 1"))
    fresh = admitted_session_factory(role_db["urls"]["routine"], new_epoch)
    try:
        with fresh() as session:
            assert session.scalar(text("SELECT 1")) == 1
        # Simulate a stale database snapshot's ready admission row. The independent
        # service epoch stays new; this is not a full backup/registry restore test.
        with role_db["owner"].begin() as session:
            session.get(RuntimeAdmissionRow, True).storage_epoch = role_db["epoch"]
        with pytest.raises(ReadinessError, match="epoch mismatch"), fresh() as session:
            session.execute(text("SELECT * FROM lucy.memory_claims"))
    finally:
        fresh.kw["bind"].dispose()


def test_ambiguous_recovery_stays_closed_even_when_prepare_is_retried(
    role_db: dict[str, Any],
) -> None:
    with role_db["owner"].begin() as session:
        session.add(
            OperationRow(
                id=uuid4(),
                idempotency_key="synthetic:unknown",
                outcome="pending",
                result=None,
                created_at=datetime.now(UTC),
                completed_at=None,
            )
        )
    maintenance = MaintenanceService(role_db["owner"])
    with pytest.raises(ReadinessError, match="did not reach ready"):
        maintenance.prepare(
            storage_epoch=uuid4(),
            expected_commit=PIN,
            observed_commit=PIN,
            executors_stopped=True,
            recover_ambiguous=True,
        )
    with role_db["owner"]() as session:
        assert session.get(RuntimeAdmissionRow, True).state == "quarantined"
        assert session.get(LifecycleRow, True).state == "degraded"
        assert (
            session.scalar(
                select(OperationRow.outcome).where(
                    OperationRow.idempotency_key == "synthetic:unknown",
                )
            )
            == "ambiguous"
        )
    with pytest.raises(ReadinessError, match="require reconciliation"):
        maintenance.prepare(
            storage_epoch=uuid4(),
            expected_commit=PIN,
            observed_commit=PIN,
            executors_stopped=True,
            recover_ambiguous=True,
        )


@pytest.mark.parametrize("mode", SERVICE_ROLES)
def test_http_readiness_with_each_real_identity_and_closed_gate(
    role_db: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    url = role_db["urls"][mode]
    monkeypatch.setenv("LUCY_ENVIRONMENT", "production")
    monkeypatch.setenv("LUCY_SERVICE_MODE", mode)
    monkeypatch.setenv("LUCY_STORAGE_EPOCH", str(role_db["epoch"]))
    monkeypatch.setenv("LUCY_DATABASE_URL", url)
    # This test isolates PostgreSQL role/readiness checks, not cloud providers.
    monkeypatch.setattr(api, "deletion_journal_from_environment", lambda: None)
    try:
        with TestClient(api.app) as client:
            assert client.get("/ready").status_code == 200
            MaintenanceService(role_db["owner"]).quarantine()
            assert client.get("/health").status_code == 200
            result = client.get("/ready")
            assert result.status_code == 503
            assert result.json() == {"detail": "Lucy storage is not admitted"}
    finally:
        api._readiness_sessions(url).kw["bind"].dispose()
        api._readiness_sessions.cache_clear()


def test_http_request_rechecks_admission_after_readiness_passed(
    role_db: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LUCY_SERVICE_MODE", "routine")
    monkeypatch.setenv("LUCY_ADAPTER_TOKEN", "synthetic-token")
    admitted = admitted_session_factory(role_db["urls"]["routine"], role_db["epoch"])
    ServiceReadiness(
        role_db["sessions"]["routine"],
        mode="routine",
        storage_epoch=role_db["epoch"],
    ).check()
    # Model the interval after the preflight read returned an admitted factory.
    monkeypatch.setattr(api, "_ready_sessions", lambda: admitted)
    MaintenanceService(role_db["owner"]).quarantine()
    with TestClient(api.app) as client:
        result = client.post(
            "/v1/memory/lookup",
            json={"query": "synthetic-private-query"},
            headers={"Authorization": "Bearer synthetic-token"},
        )
    assert result.status_code == 503
    assert result.json() == {"detail": "Lucy storage is not admitted"}


def test_admitted_transactions_override_stale_snapshot_isolation_defaults(
    role_db: dict[str, Any],
) -> None:
    admin = create_engine(role_db["urls"]["admin"])
    try:
        with admin.begin() as connection:
            connection.execute(
                text(
                    "ALTER ROLE test_routine IN DATABASE lucy_roles_test "
                    "SET default_transaction_isolation='repeatable read'",
                )
            )
        admitted = admitted_session_factory(role_db["urls"]["routine"], role_db["epoch"])
        with admitted() as session:
            assert session.scalar(text("SHOW transaction_isolation")) == "read committed"
    finally:
        with admin.begin() as connection:
            connection.execute(
                text(
                    "ALTER ROLE test_routine IN DATABASE lucy_roles_test "
                    "RESET default_transaction_isolation",
                )
            )
        admin.dispose()
