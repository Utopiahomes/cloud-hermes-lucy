"""Read-only service admission. Restarting a service never performs recovery."""

from __future__ import annotations

import os
from functools import lru_cache
from uuid import UUID

from sqlalchemy import Connection, create_engine, event, text
from sqlalchemy.orm import Session, SessionTransaction, sessionmaker

from lucy.db.session import _psycopg_url
from lucy.deletion_journal import DeletionJournal, check_journal_admission

SCHEMA_REVISION = "0021_recovery_capture_safety"
R1_SCHEMA_REVISION = "0043_r1_provider_cost_admission"
SERVICE_ROLES = {
    "routine": "lucy_routine",
    "policy": "lucy_policy",
    "evidence": "lucy_evidence_reader",
    "deletion": "lucy_evidence_deleter",
}
SERVICE_MODES = {*SERVICE_ROLES, "all-local"}
SECURITY_BASELINES = {"v1.2", "v1.3"}
ADMISSION_LOCK = 0x4C5543594144


class ReadinessError(RuntimeError):
    """Safe, content-free diagnostic; never include a URL or credential."""


def service_mode_from_environment() -> str:
    production = (
        os.getenv("LUCY_ENVIRONMENT") == "production"
        or os.getenv("LUCY_ARCHIVE_BACKEND") == "aws-kms-dynamodb"
    )
    mode = os.getenv("LUCY_SERVICE_MODE", "" if production else "all-local").strip()
    if mode not in SERVICE_MODES or (production and mode == "all-local"):
        raise ReadinessError("explicit isolated service identity required")
    return mode


def security_baseline_from_environment() -> str:
    baseline = os.getenv("LUCY_SECURITY_BASELINE", "v1.2").strip()
    if baseline not in SECURITY_BASELINES:
        raise ReadinessError("security baseline is missing or invalid")
    return baseline


def expected_database_login_from_environment(baseline: str) -> str | None:
    value = os.getenv("LUCY_EXPECTED_DATABASE_LOGIN", "").strip()
    if baseline == "v1.2":
        return value or None
    if not value or len(value) > 63:
        raise ReadinessError("expected realm database identity is missing or invalid")
    return value


def expected_storage_epoch(mode: str) -> UUID | None:
    value = os.getenv("LUCY_STORAGE_EPOCH", "").strip()
    if not value and mode == "all-local":
        return None
    try:
        return UUID(value)
    except ValueError as exc:
        raise ReadinessError("independent storage epoch is missing or invalid") from exc


class ServiceReadiness:
    def __init__(
        self,
        sessions: sessionmaker[Session],
        *,
        mode: str,
        storage_epoch: UUID | None,
        journal: DeletionJournal | None = None,
        baseline: str = "v1.2",
        expected_database_login: str | None = None,
    ) -> None:
        if mode not in SERVICE_MODES or (mode != "all-local" and storage_epoch is None):
            raise ReadinessError("service admission configuration is incomplete")
        self._sessions = sessions
        self._mode = mode
        self._epoch = storage_epoch
        self._journal = journal
        if baseline not in SECURITY_BASELINES:
            raise ReadinessError("security baseline is missing or invalid")
        if baseline == "v1.3" and not expected_database_login:
            raise ReadinessError("expected realm database identity is missing or invalid")
        self._baseline = baseline
        self._expected_database_login = expected_database_login

    def check(self) -> None:
        with self._sessions.begin() as session:
            # Guard against future accidental writes in this path as well.
            session.execute(text("SET TRANSACTION READ ONLY"))
            session.execute(
                text("SELECT pg_advisory_xact_lock_shared(:key)"), {"key": ADMISSION_LOCK}
            )
            if self._mode != "all-local":
                self._check_identity(session)
            revisions = list(
                session.scalars(
                    text(
                        "SELECT version_num FROM public.alembic_version",
                    )
                )
            )
            expected_revision = R1_SCHEMA_REVISION if self._baseline == "v1.3" else SCHEMA_REVISION
            if revisions != [expected_revision]:
                raise ReadinessError("database schema is not the reviewed revision")
            admission = session.execute(
                text(
                    "SELECT state, storage_epoch FROM lucy.runtime_admission "
                    "WHERE singleton IS TRUE"
                )
            ).one_or_none()
            if admission is None:
                raise ReadinessError("storage admission row is unavailable")
            if admission.state != "ready":
                raise ReadinessError("storage is quarantined")
            if self._epoch is not None and admission.storage_epoch != self._epoch:
                raise ReadinessError("storage epoch mismatch")
            lifecycle = session.execute(
                text("SELECT state FROM lucy.lifecycle WHERE singleton IS TRUE")
            ).one_or_none()
            if lifecycle is None:
                raise ReadinessError("control-plane recovery row is unavailable")
            if lifecycle.state != "ready":
                raise ReadinessError("control-plane recovery is not ready")
            if self._baseline == "v1.2" and self._mode in {"routine", "all-local"}:
                check_journal_admission(session.connection(), self._journal)

    def _check_identity(self, session: Session) -> None:
        if self._expected_database_login is not None:
            actual_login = session.scalar(text("SELECT session_user"))
            if actual_login != self._expected_database_login:
                raise ReadinessError("service database identity mismatch")
        elevated = session.scalar(
            text(
                "SELECT rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls "
                "FROM pg_roles WHERE rolname = current_user"
            )
        )
        if elevated is not False:
            raise ReadinessError("service login has administrative attributes")
        memberships = set(
            session.scalars(
                text(
                    "SELECT rolname FROM pg_roles WHERE "
                    "rolname IN ('lucy_routine','lucy_policy','lucy_evidence_reader',"
                    "'lucy_evidence_deleter','lucy_app') "
                    "AND pg_has_role(current_user, oid, 'MEMBER')"
                )
            )
        )
        if memberships:
            raise ReadinessError("v1.2 service login has inherited capability membership")
        elevated_storage = session.scalar(
            text(
                "SELECT has_database_privilege(current_user, current_database(), 'CREATE') "
                "OR has_schema_privilege(current_user, 'lucy', 'CREATE') "
                "OR has_schema_privilege(current_user, 'public', 'CREATE')"
            )
        )
        if elevated_storage:
            raise ReadinessError("service login can administer storage")
        if self._baseline == "v1.3":
            self._check_v13_identity(session)
            return
        forbidden = [
            ("lucy.deletion_journal_binding", "INSERT,UPDATE,DELETE,TRUNCATE"),
            ("lucy.deletion_journal_receipts", "UPDATE,DELETE,TRUNCATE"),
            ("lucy.evidence_derivations", "UPDATE,DELETE,TRUNCATE"),
            ("lucy.claim_sources", "UPDATE,DELETE,TRUNCATE"),
            ("lucy.proposal_sources", "UPDATE,DELETE,TRUNCATE"),
            ("lucy.correction_sources", "UPDATE,DELETE,TRUNCATE"),
            ("lucy.runtime_admission", "INSERT,UPDATE,DELETE,TRUNCATE"),
            ("lucy.lifecycle", "INSERT,UPDATE,DELETE,TRUNCATE"),
            ("lucy.startup_runs", "INSERT,UPDATE,DELETE,TRUNCATE"),
            ("lucy.evidence", "UPDATE,DELETE,TRUNCATE"),
            ("lucy.audit_events", "UPDATE,DELETE,TRUNCATE"),
            ("lucy.capture_receipts", "UPDATE,DELETE,TRUNCATE"),
            ("public.alembic_version", "INSERT,UPDATE,DELETE,TRUNCATE"),
        ]
        if self._mode != "deletion":
            forbidden.append(("lucy.deletion_journal_receipts", "INSERT"))
        if self._mode in {"routine", "policy"}:
            forbidden.append(("lucy.evidence_payloads", "SELECT,UPDATE,DELETE,TRUNCATE"))
        if self._mode in {"policy", "evidence"}:
            forbidden.append(("lucy.memory_claims", "INSERT,UPDATE,DELETE,TRUNCATE"))
        if self._mode == "policy":
            forbidden.append(("lucy.memory_claims", "SELECT"))
        if self._mode == "evidence":
            forbidden.append(("lucy.evidence_payloads", "INSERT,UPDATE,DELETE,TRUNCATE"))
        if self._mode != "routine":
            forbidden.extend(
                (f"lucy.{table}", "INSERT")
                for table in (
                    "evidence_derivations",
                    "claim_sources",
                    "proposal_sources",
                    "correction_sources",
                )
            )
        v12_direct_access_forbidden = (
            "security_contract_epochs",
            "owner_interaction_assertions_v1",
            "sensitive_action_permits_v2",
            "deletion_target_manifests_v1",
            "deletion_manifest_targets_v1",
            "executor_bindings_v1",
            "sensitive_operations_v1",
            "sensitive_execution_grants_v1",
            "executor_receipt_attestations_v1",
            "deletion_finality_v1",
            "sensitive_operation_events_v1",
        )
        forbidden.extend(
            (f"lucy.{table}", "SELECT,INSERT,UPDATE,DELETE,TRUNCATE")
            for table in v12_direct_access_forbidden
        )
        if self._mode != "routine":
            # V1.2 policy/evidence/deletion are execute-only boundaries. All
            # application data access is inside their exact security-definer
            # functions; even a future accidental column grant must close
            # admission before the service accepts work.
            nonroutine_direct_access_forbidden = (
                "operations",
                "budget_accounts",
                "budget_reservations",
                "approval_requests",
                "memory_claims",
                "memory_entities",
                "memory_relationships",
                "working_contexts",
                "memory_corrections",
                "memory_write_proposals",
                "action_executions",
                "conversation_capture_states",
                "conversation_turns",
                "capture_receipts",
                "evidence",
                "evidence_payloads",
                "evidence_tombstones",
                "evidence_derivations",
                "claim_sources",
                "proposal_sources",
                "correction_sources",
                "audit_head",
                "audit_events",
                "startup_runs",
                "deletion_journal_binding",
                "deletion_journal_receipts",
                "evidence_deletion_fences_v1",
            )
            forbidden.extend(
                (f"lucy.{table}", "SELECT,INSERT,UPDATE,DELETE,TRUNCATE")
                for table in nonroutine_direct_access_forbidden
            )
        for table, privileges in forbidden:
            table_grant = session.scalar(
                text("SELECT has_table_privilege(current_user, :table, :privileges)"),
                {"table": table, "privileges": privileges},
            )
            columns = ",".join(
                p for p in privileges.split(",") if p in {"SELECT", "INSERT", "UPDATE"}
            )
            column_grant = columns and session.scalar(
                text("SELECT has_any_column_privilege(current_user, :table, :privileges)"),
                {"table": table, "privileges": columns},
            )
            if table_grant or column_grant:
                raise ReadinessError("service login exceeds its reviewed capabilities")
        required_functions = {
            "policy": (
                "lucy.issue_sensitive_action_permit_v2(jsonb,jsonb,text)",
                "lucy.prepare_deletion_scope_v1(uuid,uuid,text)",
                "lucy.finalize_deletion_scope_v1(uuid,jsonb,jsonb)",
                "lucy.read_claim_digest_for_notary_v1(uuid)",
                "lucy.store_sensitive_execution_grant_v1(uuid,jsonb)",
                "lucy.attest_executor_receipt_v1(uuid,jsonb)",
            ),
            "evidence": (
                "lucy.claim_evidence_retrieval_v1(jsonb,text)",
                "lucy.reconcile_evidence_retrieval_v1(uuid)",
                "lucy.record_evidence_delivery_v1(uuid,text)",
            ),
            "deletion": (
                "lucy.claim_evidence_deletion_v1(jsonb,jsonb,text)",
                "lucy.reconcile_evidence_deletion_v1(uuid)",
            ),
        }
        for function in required_functions.get(self._mode, ()):
            if not session.scalar(
                text("SELECT has_function_privilege(session_user, :function, 'EXECUTE')"),
                {"function": function},
            ):
                raise ReadinessError("service login lacks its exact v1.2 function grants")
        # The actual service-operation matrix is exercised with separate logins
        # in PostgreSQL tests; these are the common minimum readiness grants.
        for table in ("lucy.lifecycle", "lucy.runtime_admission", "public.alembic_version"):
            if not session.scalar(
                text("SELECT has_table_privilege(current_user, :table, 'SELECT')"),
                {"table": table},
            ):
                raise ReadinessError("service login lacks readiness permissions")

    def _check_v13_identity(self, session: Session) -> None:
        # V1.3 realm logins are execute-only. The two gate tables and Alembic
        # revision contain no customer content and are the sole direct reads.
        allowed_reads = {
            "lucy.lifecycle",
            "lucy.runtime_admission",
            "public.alembic_version",
        }
        tables = session.execute(
            text(
                "SELECT n.nspname || '.' || c.relname AS relation "
                "FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                "WHERE n.nspname IN ('lucy','public') AND c.relkind IN ('r','p')"
            )
        ).scalars()
        for table in tables:
            privileges = "INSERT,UPDATE,DELETE,TRUNCATE"
            if table not in allowed_reads:
                privileges = "SELECT," + privileges
            if session.scalar(
                text("SELECT has_table_privilege(session_user, :table, :privileges)"),
                {"table": table, "privileges": privileges},
            ):
                raise ReadinessError("realm service login exceeds execute-only capabilities")
        for table in allowed_reads:
            if not session.scalar(
                text("SELECT has_table_privilege(session_user, :table, 'SELECT')"),
                {"table": table},
            ):
                raise ReadinessError("realm service login lacks readiness permissions")
        required_functions = {
            "routine": (
                "lucy.write_scoped_memory_claim_v1(text,text,text,text,bigint)",
                "lucy.search_scoped_memory_v1(text,integer)",
                "lucy.claim_capturable_scoped_archive_v1(text,text,text,text,text,jsonb)",
                "lucy.record_scoped_archive_aws_outcome_v1(uuid,jsonb,text)",
                "lucy.reconcile_capturable_scoped_archive_v1(uuid)",
            ),
            "policy": (
                "lucy.issue_sensitive_action_permit_v3(jsonb,text)",
                "lucy.read_sensitive_permit_authority_v1(uuid,uuid,text,uuid,bigint)",
                "lucy.read_claimed_sensitive_authority_v1(uuid)",
                "lucy.read_claimed_deletion_authority_v1(uuid)",
                "lucy.store_scoped_deletion_manifest_v3(uuid,jsonb)",
                "lucy.store_sensitive_execution_grant_v2(uuid,jsonb)",
                "lucy.attest_executor_receipt_v2(uuid,jsonb)",
            ),
            "evidence": (
                "lucy.read_sensitive_action_permit_v3(uuid,text)",
                "lucy.claim_sensitive_operation_v2(uuid,text)",
                "lucy.read_sensitive_operation_status_v1(uuid)",
                "lucy.freeze_claimed_evidence_package_v2(uuid)",
                "lucy.reconcile_sensitive_operation_v2(uuid)",
            ),
            "deletion": (
                "lucy.read_sensitive_action_permit_v3(uuid,text)",
                "lucy.claim_sensitive_operation_v2(uuid,text)",
                "lucy.read_sensitive_operation_status_v1(uuid)",
                "lucy.reconcile_scoped_deletion_v2(uuid)",
            ),
        }
        for function in required_functions.get(self._mode, ()):
            if not session.scalar(
                text("SELECT has_function_privilege(session_user, :function, 'EXECUTE')"),
                {"function": function},
            ):
                raise ReadinessError("realm service login lacks its exact function grants")


class AdmittedSession(Session):
    """Only HTTP service operations use this class; maintenance never does."""


@event.listens_for(AdmittedSession, "after_begin")
def _check_transaction_admission(
    session: Session,
    transaction: SessionTransaction,
    connection: Connection,
) -> None:
    if transaction.nested:
        return
    # Advisory locks do not require UPDATE on the operator-owned gate table.
    # Always acquire admission before retention/operation locks.
    lock = (
        "pg_advisory_xact_lock"
        if session.info.get("deletion_execution")
        else "pg_advisory_xact_lock_shared"
    )
    connection.execute(text(f"SELECT {lock}(:key)"), {"key": ADMISSION_LOCK})
    row = connection.execute(
        text(
            "SELECT a.state, a.storage_epoch, l.state AS lifecycle "
            "FROM lucy.runtime_admission a CROSS JOIN lucy.lifecycle l "
            "WHERE a.singleton AND l.singleton"
        )
    ).one_or_none()
    if row is None or row.state != "ready" or row.lifecycle != "ready":
        raise ReadinessError("storage is quarantined")
    epoch = session.info.get("storage_epoch")
    if epoch is not None and row.storage_epoch != epoch:
        raise ReadinessError("storage epoch mismatch")
    if session.info.get("journal_required", True):
        check_journal_admission(connection, session.info.get("deletion_journal"))


@lru_cache(maxsize=8)
def admitted_session_factory(
    database_url: str,
    storage_epoch: UUID | None,
    journal: DeletionJournal | None = None,
    journal_required: bool = True,
) -> sessionmaker[Session]:
    return sessionmaker(
        create_engine(
            _psycopg_url(database_url),
            pool_pre_ping=True,
            isolation_level="READ COMMITTED",
        ),
        class_=AdmittedSession,
        expire_on_commit=False,
        info={
            "storage_epoch": storage_epoch,
            "deletion_journal": journal,
            "journal_required": journal_required,
        },
    )
