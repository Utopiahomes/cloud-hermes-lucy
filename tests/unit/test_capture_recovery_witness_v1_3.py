from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import pytest

from deploy.aws.capture_recovery_witness_v1_3 import (
    RecoveryWitnessError,
    capture,
)
from lucy.recovery_journal import RecoveryStreamBindingV1, RecoveryStreamKind

ACCOUNT = "123456789012"
MANIFEST = "a" * 64


def _binding(kind: RecoveryStreamKind, stream: str) -> RecoveryStreamBindingV1:
    return RecoveryStreamBindingV1(
        stream_kind=kind,
        stream_id=UUID(stream),
        authority_epoch=1,
        independent_store_id=(
            f"arn:aws:dynamodb:us-east-1:{ACCOUNT}:table/{kind.value}-table"
        ),
        writer_identity=f"arn:aws:iam::{ACCOUNT}:role/{kind.value}-writer",
        recovery_identity=f"arn:aws:iam::{ACCOUNT}:role/recovery",
        binding_manifest_digest=MANIFEST,
    )


class FakeDynamo:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def get_item(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(dict(kwargs))
        table = str(kwargs["TableName"])
        kind = "authority" if table == "authority-table" else "cost"
        stream = (
            "11111111-1111-4111-8111-111111111111"
            if kind == "authority"
            else "22222222-2222-4222-8222-222222222222"
        )
        return {
            "Item": {
                "stream_kind": {"S": kind},
                "stream_id": {"S": stream},
                "authority_epoch": {"N": "1"},
                "independent_store_id": {
                    "S": f"arn:aws:dynamodb:us-east-1:{ACCOUNT}:table/{table}"
                },
                "binding_manifest_digest": {"S": MANIFEST},
                "sequence": {"N": "0"},
                "event_digest": {"S": "0" * 64},
            }
        }

    def put_item(self, **_kwargs: object) -> dict[str, object]:
        raise AssertionError("witness capture cannot write")

    def transact_write_items(self, **_kwargs: object) -> dict[str, object]:
        raise AssertionError("witness capture cannot write")


def test_capture_exact_reads_two_distinct_heads_without_writes() -> None:
    authority = _binding(
        RecoveryStreamKind.AUTHORITY, "11111111-1111-4111-8111-111111111111"
    )
    cost = _binding(RecoveryStreamKind.COST, "22222222-2222-4222-8222-222222222222")
    client = FakeDynamo()

    report = capture(
        authority_binding=authority,
        cost_binding=cost,
        account_id=ACCOUNT,
        identity={"Account": ACCOUNT},
        client=client,
        captured_at=datetime(2026, 9, 10, tzinfo=UTC),
    )

    assert report["authority_witness"]["sequence"] == 0
    assert report["cost_witness"]["sequence"] == 0
    assert len(report["bundle_digest"]) == 64
    assert [call["TableName"] for call in client.calls] == [
        "authority-table",
        "cost-table",
    ]
    assert all(call["ConsistentRead"] is True for call in client.calls)


def test_capture_rejects_cross_account_or_shared_manifest_drift() -> None:
    authority = _binding(
        RecoveryStreamKind.AUTHORITY, "11111111-1111-4111-8111-111111111111"
    )
    cost = _binding(RecoveryStreamKind.COST, "22222222-2222-4222-8222-222222222222")

    with pytest.raises(RecoveryWitnessError, match="boundary"):
        capture(
            authority_binding=authority,
            cost_binding=cost.model_copy(update={"binding_manifest_digest": "b" * 64}),
            account_id=ACCOUNT,
            identity={"Account": ACCOUNT},
            client=FakeDynamo(),
            captured_at=datetime(2026, 9, 10, tzinfo=UTC),
        )
