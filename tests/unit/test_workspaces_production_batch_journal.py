from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from deploy.render import workspaces_production_batch as batch
from deploy.render.workspaces_production_batch_journal import FilesystemBatchJournal
from tests.unit.test_workspaces_production_batch import ISSUED, _ledger, _plan


def test_journal_persists_receipts_and_resumes_at_exact_next_stage(tmp_path: Path) -> None:
    plan = _plan()
    path = tmp_path / "batch-journal.json"
    store = FilesystemBatchJournal(plan, path)
    store.initialize()

    expected = _ledger(plan)
    store.append_receipt(expected[0])
    store.append_receipt(expected[1])

    reloaded = FilesystemBatchJournal(plan, path).load(now=ISSUED + timedelta(minutes=15))
    assert list(reloaded.receipts) == expected[:2]
    assert batch.validate_ledger(plan, reloaded.receipts, now=ISSUED + timedelta(minutes=15)) == (
        batch.Stage.MIGRATED
    )
    assert not path.with_name(f"{path.name}.lock").exists()


def test_journal_refuses_overwrite_reorder_and_cross_batch_use(tmp_path: Path) -> None:
    plan = _plan()
    path = tmp_path / "batch-journal.json"
    store = FilesystemBatchJournal(plan, path)
    store.initialize()
    with pytest.raises(batch.BatchContractError, match="already exists"):
        store.initialize()
    with pytest.raises(batch.BatchContractError, match="missing, duplicated, or reordered"):
        store.append_receipt(_ledger(plan)[1])

    other = _plan(batch_id="22222222-2222-4222-8222-222222222222")
    with pytest.raises(batch.BatchContractError, match="different production batch"):
        FilesystemBatchJournal(other, path).load(now=ISSUED)


def test_journal_lock_fails_closed_without_removing_existing_lock(tmp_path: Path) -> None:
    plan = _plan()
    path = tmp_path / "batch-journal.json"
    store = FilesystemBatchJournal(plan, path)
    store.initialize()
    store.lock_path.write_text("operator investigation required\n", encoding="utf-8")

    with pytest.raises(batch.BatchContractError, match="inspect rather than removing"):
        store.append_receipt(_ledger(plan)[0])
    assert store.lock_path.exists()


def test_containment_is_durable_and_terminal(tmp_path: Path) -> None:
    plan = _plan()
    path = tmp_path / "batch-journal.json"
    store = FilesystemBatchJournal(plan, path)
    store.initialize()
    receipts = _ledger(plan)
    store.append_receipt(receipts[0])
    containment = batch.BatchContainmentReceiptV1(
        batch_digest=plan.digest_hex(),
        failed_stage=batch.Stage.CONTAINED,
        prior_receipt_sha256=receipts[0].digest_hex(),
        occurred_at=ISSUED + timedelta(minutes=5),
        reason="operator_abort",
        workspaces_transport_disabled=True,
        affected_autodeploy_disabled=True,
        existing_surfaces="contained",
        admission_state="quarantined",
        capture_boundary_safe=True,
        private_service="absent",
    )
    store.persist_containment(containment)

    reloaded = store.load()
    assert reloaded.containment == containment
    with pytest.raises(batch.BatchContractError, match="terminal"):
        store.append_receipt(receipts[1])
    with pytest.raises(batch.BatchContractError, match="already has terminal containment"):
        store.persist_containment(containment)


def test_tampered_journal_fails_closed(tmp_path: Path) -> None:
    plan = _plan()
    path = tmp_path / "batch-journal.json"
    store = FilesystemBatchJournal(plan, path)
    store.initialize()
    path.write_text('{"contract":"wrong"}\n', encoding="utf-8")

    with pytest.raises(batch.BatchContractError, match="journal is invalid"):
        store.load(now=ISSUED)
