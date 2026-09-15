"""Durable, local journal for the Workspaces production-batch coordinator.

The journal performs no network, database, deployment, or configuration action. It
atomically persists already-validated content-free receipts so an approved live job
can resume without repeating a completed stage. A separate exclusive lock fails
closed on concurrent use; stale locks are never removed automatically.
"""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, ValidationError

from deploy.render.workspaces_production_batch import (
    STAGE_ORDER,
    BatchContainmentReceiptV1,
    BatchContractError,
    BatchStageReceiptV1,
    WorkspacesProductionBatchV1,
    validate_containment,
    validate_ledger,
)
from lucy.contracts.canonical import canonical_json_bytes


class BatchJournalV1(BaseModel):
    """Complete resumable state for one exact production-batch digest."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    contract: Literal["lucy.workspaces-production-batch-journal.v1"] = (
        "lucy.workspaces-production-batch-journal.v1"
    )
    batch_digest: str
    receipts: tuple[BatchStageReceiptV1, ...] = ()
    containment: BatchContainmentReceiptV1 | None = None


class FilesystemBatchJournal:
    """Atomic journal store bound to one reviewed plan and one filesystem path."""

    def __init__(self, plan: WorkspacesProductionBatchV1, path: Path) -> None:
        self.plan = plan
        self.path = path
        self.lock_path = path.with_name(f"{path.name}.lock")

    def initialize(self) -> BatchJournalV1:
        journal = BatchJournalV1(batch_digest=self.plan.digest_hex())
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with self.path.open("xb") as destination:
                destination.write(canonical_json_bytes(journal.model_dump(mode="python")) + b"\n")
                destination.flush()
                os.fsync(destination.fileno())
        except FileExistsError as exc:
            raise BatchContractError("production batch journal already exists") from exc
        return journal

    def load(self, *, now: datetime | None = None) -> BatchJournalV1:
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
            journal = BatchJournalV1.model_validate(value)
        except FileNotFoundError as exc:
            raise BatchContractError("production batch journal does not exist") from exc
        except (OSError, ValueError, ValidationError) as exc:
            raise BatchContractError("production batch journal is invalid") from exc
        self._validate(journal, now=now)
        return journal

    def append_receipt(self, receipt: BatchStageReceiptV1) -> None:
        with self._lock():
            journal = self.load(now=receipt.completed_at)
            if journal.containment is not None:
                raise BatchContractError("contained production batch is terminal")
            candidate = journal.model_copy(update={"receipts": (*journal.receipts, receipt)})
            self._validate(candidate, now=receipt.completed_at)
            self._replace(candidate)

    def persist_containment(self, containment: BatchContainmentReceiptV1) -> None:
        with self._lock():
            journal = self.load(now=containment.occurred_at)
            if journal.containment is not None:
                raise BatchContractError("production batch already has terminal containment")
            candidate = journal.model_copy(update={"containment": containment})
            self._validate(candidate, now=containment.occurred_at)
            self._replace(candidate)

    def _validate(self, journal: BatchJournalV1, *, now: datetime | None = None) -> None:
        if journal.batch_digest != self.plan.digest_hex():
            raise BatchContractError("journal belongs to a different production batch")
        validation_time = now
        if validation_time is None:
            if journal.containment is not None:
                validation_time = journal.containment.occurred_at
            elif len(journal.receipts) == len(STAGE_ORDER):
                validation_time = journal.receipts[-1].completed_at
            else:
                validation_time = datetime.now(UTC)
        validate_ledger(self.plan, journal.receipts, now=validation_time)
        if journal.containment is not None:
            validate_containment(self.plan, journal.receipts, journal.containment)

    @contextmanager
    def _lock(self) -> Iterator[None]:
        try:
            lock = self.lock_path.open("xb")
        except FileExistsError as exc:
            raise BatchContractError(
                "production batch journal is locked; inspect rather than removing the lock blindly"
            ) from exc
        try:
            lock.write(b"exclusive production batch journal lock\n")
            lock.flush()
            os.fsync(lock.fileno())
            lock.close()
            yield
        finally:
            lock.close()
            with suppress(FileNotFoundError):
                self.lock_path.unlink()

    def _replace(self, journal: BatchJournalV1) -> None:
        data = canonical_json_bytes(journal.model_dump(mode="python")) + b"\n"
        temporary: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb", prefix=f".{self.path.name}.", suffix=".tmp", dir=self.path.parent,
                delete=False,
            ) as destination:
                temporary = Path(destination.name)
                destination.write(data)
                destination.flush()
                os.fsync(destination.fileno())
            os.replace(temporary, self.path)
        finally:
            if temporary is not None and temporary.exists():
                temporary.unlink()
