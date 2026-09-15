from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from lucy.public_diagnostics import PublicDiagnosticReceipt, PublicDiagnosticStore

TRACE = UUID("24512180-a368-4ad0-a167-44082ae66c66")


def _receipt(trace_id: UUID = TRACE) -> PublicDiagnosticReceipt:
    return PublicDiagnosticReceipt(
        contract="lucy.public-diagnostic-receipt.v1",
        trace_id=trace_id,
        recorded_at=datetime(2026, 9, 15, tzinfo=UTC),
        environment="staging",
        cloud_release_id="a" * 40,
        snapshot_version=2,
        snapshot_digest="b" * 64,
        request_latency_ms=250,
        outcome="completed",
    )


def test_content_free_store_expires_and_evicts_receipts() -> None:
    now = [0.0]
    store = PublicDiagnosticStore(
        ttl_seconds=60,
        maximum_receipts=10,
        clock=lambda: now[0],
    )
    receipts = [
        _receipt(UUID(f"24512180-a368-4ad0-a167-44082ae66c{i:02x}"))
        for i in range(11)
    ]
    for receipt in receipts:
        now[0] += 1
        store.put(receipt)

    assert store.get(receipts[0].trace_id) is None
    assert store.get(receipts[-1].trace_id) == receipts[-1]
    assert "question" not in receipts[-1].model_dump_json()
    assert "Utopia Homes" not in receipts[-1].model_dump_json()

    now[0] += 61
    assert store.get(receipts[-1].trace_id) is None
