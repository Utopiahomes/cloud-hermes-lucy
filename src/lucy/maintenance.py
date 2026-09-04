"""Explicit offline maintenance; never called by an HTTP service startup."""

from __future__ import annotations

import argparse
import os
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session, sessionmaker

from lucy.archive_crypto import ArchiveKeyStore, archive_key_store_from_environment
from lucy.authorization import SensitiveActionPermitVerifier
from lucy.contracts import OperationOutcome, RejoiningState
from lucy.db import create_session_factory
from lucy.db.models import (
    DeletionJournalBindingRow,
    DeletionJournalReceiptRow,
    EvidencePayloadRow,
    OperationRow,
    RuntimeAdmissionRow,
)
from lucy.deletion_journal import (
    GENESIS,
    DeletionJournal,
    DeletionJournalError,
    check_journal_admission,
    deletion_journal_from_environment,
)
from lucy.evidence import EvidenceService
from lucy.provenance import verify_archive_provenance
from lucy.readiness import ADMISSION_LOCK, ReadinessError
from lucy.rejoining import RejoiningService
from lucy.retention import retention_fence
from lucy.runtime import _expected_commit

MAINTENANCE_LOCK = 0x4C5543594D53


def _permit_verifier_for_recovery(
    *, recover_deletions: bool
) -> SensitiveActionPermitVerifier | None:
    """Load legacy permit trust only when replaying accepted deletions."""
    if not recover_deletions:
        return None
    return SensitiveActionPermitVerifier.from_environment()


class MaintenanceService:
    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self._sessions = sessions

    def quarantine(self) -> None:
        """Wait for admitted transactions, then persistently block new ones."""
        with self._sessions.begin() as guard:
            guard.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": MAINTENANCE_LOCK})
            self._quarantine()

    def _quarantine(self) -> None:
        with self._sessions.begin() as session:
            session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": ADMISSION_LOCK})
            row = session.get(RuntimeAdmissionRow, True)
            if row is None:
                raise ReadinessError("storage admission row is missing")
            row.state = "quarantined"
            row.updated_at = datetime.now(UTC)

    def prepare(
        self,
        *,
        storage_epoch: UUID,
        expected_commit: str,
        observed_commit: str,
        executors_stopped: bool = False,
        recover_ambiguous: bool = False,
        key_store: ArchiveKeyStore | None = None,
        journal: DeletionJournal | None = None,
        recover_deletions: bool = False,
        permit_verifier: SensitiveActionPermitVerifier | None = None,
    ) -> None:
        # Keep a separate lock-only transaction alive across the durable close,
        # verification, recovery, and reopen commits. A crash releases its lock
        # without rolling back the already committed quarantine state.
        with self._sessions.begin() as guard:
            guard.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": MAINTENANCE_LOCK})
            self._prepare(
                storage_epoch=storage_epoch,
                expected_commit=expected_commit,
                observed_commit=observed_commit,
                executors_stopped=executors_stopped,
                recover_ambiguous=recover_ambiguous,
                key_store=key_store,
                journal=journal,
                recover_deletions=recover_deletions,
                permit_verifier=permit_verifier,
            )

    def _prepare(
        self,
        *,
        storage_epoch: UUID,
        expected_commit: str,
        observed_commit: str,
        executors_stopped: bool,
        recover_ambiguous: bool,
        key_store: ArchiveKeyStore | None,
        journal: DeletionJournal | None,
        recover_deletions: bool,
        permit_verifier: SensitiveActionPermitVerifier | None,
    ) -> None:
        if not executors_stopped:
            raise ReadinessError("operator must confirm all executors are stopped")
        with self._sessions() as session:
            admission = session.get(RuntimeAdmissionRow, True)
            if admission is None:
                raise ReadinessError("storage admission row is missing")
            if admission.storage_epoch == storage_epoch:
                if admission.state != "ready":
                    raise ReadinessError(
                        "maintenance requires a fresh independently configured epoch"
                    )
                if observed_commit != expected_commit:
                    raise ReadinessError("Hermes pin mismatch")
                # Render can restart a successfully completed one-shot command.
                # An exact epoch replay is already durable and must not close
                # admission again merely to rediscover that it completed.
                return
        self._quarantine()
        with self._sessions() as session:
            # Idle connection pools count: stop the services, not just requests.
            connected = session.scalar(
                text(
                    "SELECT count(*) FROM pg_stat_activity a JOIN pg_roles u ON u.oid=a.usesysid "
                    "WHERE a.datname=current_database() AND a.pid<>pg_backend_pid() "
                    "AND NOT u.rolsuper AND u.rolname<>current_user "
                    "AND has_schema_privilege(u.oid,'lucy','USAGE')"
                )
            )
            if connected:
                raise ReadinessError("service database sessions are still connected")
            row = session.get(RuntimeAdmissionRow, True)
            if row is None or row.storage_epoch == storage_epoch:
                raise ReadinessError("maintenance requires a fresh independently configured epoch")
        self._reconcile_journal(
            journal,
            key_store,
            recover_deletions=recover_deletions,
            permit_verifier=permit_verifier,
        )
        with self._sessions() as session:
            pending = session.scalar(
                select(func.count())
                .select_from(OperationRow)
                .where(
                    OperationRow.outcome == OperationOutcome.PENDING,
                )
            )
            if pending and not recover_ambiguous:
                raise ReadinessError("pending work requires explicit ambiguous-recovery review")
            unresolved = session.scalar(
                select(func.count())
                .select_from(OperationRow)
                .where(
                    OperationRow.outcome == OperationOutcome.AMBIGUOUS,
                )
            )
            if unresolved:
                raise ReadinessError("ambiguous outcomes require reconciliation before admission")
            try:
                verify_archive_provenance(session)
            except (PermissionError, LookupError) as exc:
                raise ReadinessError(
                    "archive provenance review required; storage quarantined"
                ) from exc
            refs = list(session.scalars(select(EvidencePayloadRow.key_ref)))
            if refs and key_store is None:
                raise ReadinessError("archive registry verification is required")
            if key_store is not None and any(key_store.get(ref) is None for ref in refs):
                raise ReadinessError("archive registry mismatch; storage remains quarantined")
        result = RejoiningService(self._sessions, expected_hermes_commit=expected_commit).run(
            observed_hermes_commit=observed_commit,
        )
        if result.state != RejoiningState.READY:
            raise ReadinessError("control-plane recovery did not reach ready")
        with self._sessions.begin() as session:
            session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": ADMISSION_LOCK})
            row = session.get(RuntimeAdmissionRow, True)
            if row is None or row.state != "quarantined":
                raise ReadinessError("storage admission changed during maintenance")
            check_journal_admission(session.connection(), journal)
            row.state = "ready"
            row.storage_epoch = storage_epoch
            row.updated_at = datetime.now(UTC)

    def _reconcile_journal(
        self,
        journal: DeletionJournal | None,
        key_store: ArchiveKeyStore | None,
        *,
        recover_deletions: bool,
        permit_verifier: SensitiveActionPermitVerifier | None,
    ) -> None:
        if journal is None:
            with self._sessions() as session:
                check_journal_admission(session.connection(), None)
            return
        head = journal.head()
        if key_store is None or key_store.registry_identity != head.registry_id:
            raise DeletionJournalError("identity-bound archive registry is required")
        with self._sessions.begin() as session:
            binding = session.get(DeletionJournalBindingRow, True)
            if binding is None:
                # No automatic adoption of an old/nonempty journal into another
                # database. A pre-binding restore needs a reviewed identity repair.
                if head.sequence or session.scalar(
                    select(DeletionJournalReceiptRow.sequence).limit(1)
                ):
                    raise DeletionJournalError("nonempty journal requires existing storage binding")
                session.add(
                    DeletionJournalBindingRow(
                        singleton=True,
                        journal_id=head.journal_id,
                        registry_id=head.registry_id,
                    )
                )
            elif (binding.journal_id, binding.registry_id) != (head.journal_id, head.registry_id):
                raise DeletionJournalError("deletion journal binding mismatch")
            receipts = list(
                session.scalars(
                    select(DeletionJournalReceiptRow).order_by(
                        DeletionJournalReceiptRow.sequence,
                    )
                )
            )
        if len(receipts) > head.sequence:
            raise DeletionJournalError("independent deletion journal appears rolled back")
        if head.sequence and permit_verifier is None:
            raise DeletionJournalError("deletion journal signature verification required")
        # Validate the entire prefix before destroying anything. Receipt order,
        # intent signatures and hash chain must agree, including restored backups.
        entries = []
        previous = GENESIS
        for sequence in range(1, head.sequence + 1):
            entry = journal.entry(sequence)
            if entry.sequence != sequence or entry.previous_digest != previous:
                raise DeletionJournalError("deletion journal chain mismatch")
            assert permit_verifier is not None
            permit_verifier.verify_signature(entry.intent.permit)
            if sequence <= len(receipts):
                receipt = receipts[sequence - 1]
                if (receipt.sequence, receipt.digest, receipt.intent_id, receipt.operation_id) != (
                    sequence,
                    entry.digest,
                    entry.intent.intent_id,
                    entry.intent.operation_id,
                ):
                    raise DeletionJournalError("deletion journal receipt mismatch")
            entries.append(entry)
            previous = entry.digest
        if previous != head.digest or journal.head() != head:
            raise DeletionJournalError("deletion journal changed during maintenance")
        if len(receipts) < len(entries) and not recover_deletions:
            raise DeletionJournalError("accepted deletions require explicit recovery")
        for entry in entries[len(receipts) :]:
            assert permit_verifier is not None
            with self._sessions.begin() as session:
                session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": ADMISSION_LOCK})
                retention_fence(session, deleting=True)
                EvidenceService(
                    self._sessions,
                    None,
                    key_store,
                    permit_verifier,
                    journal=journal,
                )._apply_accepted_deletion(session, entry)
        with self._sessions() as session:
            check_journal_admission(session.connection(), journal)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("quarantine", "prepare"))
    parser.add_argument("--storage-epoch", type=UUID)
    parser.add_argument("--confirm-executors-stopped", action="store_true")
    parser.add_argument("--recover-ambiguous", action="store_true")
    parser.add_argument("--recover-deletions", action="store_true")
    args = parser.parse_args()
    sessions = create_session_factory(os.environ["LUCY_MAINTENANCE_DATABASE_URL"])
    maintenance = MaintenanceService(sessions)
    if args.action == "quarantine":
        maintenance.quarantine()
    else:
        if args.storage_epoch is None:
            parser.error("prepare requires --storage-epoch")
        key_store = (
            archive_key_store_from_environment() if os.getenv("LUCY_ARCHIVE_BACKEND") else None
        )
        maintenance.prepare(
            storage_epoch=args.storage_epoch,
            expected_commit=_expected_commit(),
            observed_commit=os.environ["LUCY_OBSERVED_HERMES_COMMIT"],
            executors_stopped=args.confirm_executors_stopped,
            recover_ambiguous=args.recover_ambiguous,
            key_store=key_store,
            journal=deletion_journal_from_environment(),
            recover_deletions=args.recover_deletions,
            permit_verifier=_permit_verifier_for_recovery(
                recover_deletions=args.recover_deletions
            ),
        )
    print(f"Storage maintenance {args.action} completed; no model or user messages were replayed.")


if __name__ == "__main__":
    main()
