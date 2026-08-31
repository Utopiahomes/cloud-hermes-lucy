"""Read-only service admission. Restarting a service never performs recovery."""

from __future__ import annotations

import os
from functools import lru_cache
from uuid import UUID

from sqlalchemy import Connection, create_engine, event, text
from sqlalchemy.orm import Session, SessionTransaction, sessionmaker

from lucy.db.models import LifecycleRow, RuntimeAdmissionRow
from lucy.deletion_journal import DeletionJournal, check_journal_admission

SCHEMA_REVISION = "0016_deletion_journal"
SERVICE_ROLES = {
    "routine": "lucy_routine",
    "policy": "lucy_policy",
    "evidence": "lucy_evidence_reader",
    "deletion": "lucy_evidence_deleter",
}
SERVICE_MODES = {*SERVICE_ROLES, "all-local"}
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
    ) -> None:
        if mode not in SERVICE_MODES or (mode != "all-local" and storage_epoch is None):
            raise ReadinessError("service admission configuration is incomplete")
        self._sessions = sessions
        self._mode = mode
        self._epoch = storage_epoch
        self._journal = journal

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
            if revisions != [SCHEMA_REVISION]:
                raise ReadinessError("database schema is not the reviewed revision")
            admission = session.get(RuntimeAdmissionRow, True)
            if admission is None or admission.state != "ready":
                raise ReadinessError("storage is quarantined")
            if self._epoch is not None and admission.storage_epoch != self._epoch:
                raise ReadinessError("storage epoch mismatch")
            lifecycle = session.get(LifecycleRow, True)
            if lifecycle is None or lifecycle.state != "ready":
                raise ReadinessError("control-plane recovery is not ready")
            if self._mode != "policy":
                check_journal_admission(session.connection(), self._journal)

    def _check_identity(self, session: Session) -> None:
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
        if memberships != {SERVICE_ROLES[self._mode]}:
            raise ReadinessError("service login has wrong or compound capability membership")
        elevated_storage = session.scalar(
            text(
                "SELECT has_database_privilege(current_user, current_database(), 'CREATE') "
                "OR has_schema_privilege(current_user, 'lucy', 'CREATE') "
                "OR has_schema_privilege(current_user, 'public', 'CREATE')"
            )
        )
        if elevated_storage:
            raise ReadinessError("service login can administer storage")
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
        # The actual service-operation matrix is exercised with separate logins
        # in PostgreSQL tests; these are the common minimum readiness grants.
        for table in ("lucy.lifecycle", "lucy.runtime_admission", "public.alembic_version"):
            if not session.scalar(
                text("SELECT has_table_privilege(current_user, :table, 'SELECT')"),
                {"table": table},
            ):
                raise ReadinessError("service login lacks readiness permissions")


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
        create_engine(database_url, pool_pre_ping=True, isolation_level="READ COMMITTED"),
        class_=AdmittedSession,
        expire_on_commit=False,
        info={
            "storage_epoch": storage_epoch,
            "deletion_journal": journal,
            "journal_required": journal_required,
        },
    )
