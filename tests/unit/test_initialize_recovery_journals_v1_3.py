from __future__ import annotations

from copy import deepcopy
from typing import NoReturn
from uuid import UUID

import pytest
from botocore.exceptions import ClientError  # type: ignore[import-untyped]

from deploy.aws.initialize_recovery_journals_v1_3 import initialize_pair
from lucy.recovery_journal import RecoveryStreamBindingV1, RecoveryStreamKind

ACCOUNT = "429870640638"
MANIFEST = "a" * 64


class FakeDynamo:
    def __init__(self) -> None:
        self.items: dict[tuple[str, str], dict[str, object]] = {}

    def put_item(self, **kwargs: object) -> dict[str, object]:
        item = kwargs["Item"]
        assert isinstance(item, dict)
        key = (_value(item, "pk"), _value(item, "sk"))
        if key in self.items:
            _conditional_failure()
        self.items[key] = deepcopy(item)
        return {}

    def get_item(self, **kwargs: object) -> dict[str, object]:
        assert kwargs["ConsistentRead"] is True
        key_value = kwargs["Key"]
        assert isinstance(key_value, dict)
        key = (_value(key_value, "pk"), _value(key_value, "sk"))
        item = self.items.get(key)
        return {} if item is None else {"Item": deepcopy(item)}

    def transact_write_items(self, **kwargs: object) -> dict[str, object]:
        raise AssertionError("genesis initialization must not use a transaction")


def _binding(kind: RecoveryStreamKind, stream_id: int, table: str) -> RecoveryStreamBindingV1:
    return RecoveryStreamBindingV1(
        stream_kind=kind,
        stream_id=UUID(int=stream_id),
        authority_epoch=1,
        independent_store_id=f"arn:aws:dynamodb:us-east-1:{ACCOUNT}:table/{table}",
        writer_identity=f"arn:aws:iam::{ACCOUNT}:role/lucy-{kind.value}-writer",
        recovery_identity=f"arn:aws:iam::{ACCOUNT}:role/lucy-recovery-coordinator",
        binding_manifest_digest=MANIFEST,
    )


def test_pair_initialization_is_create_only_and_idempotent() -> None:
    client = FakeDynamo()
    arguments = {
        "account_id": ACCOUNT,
        "region": "us-east-1",
        "authority_table": "lucy-authority-journal",
        "authority_binding": _binding(
            RecoveryStreamKind.AUTHORITY, 1, "lucy-authority-journal"
        ),
        "cost_table": "lucy-cost-journal",
        "cost_binding": _binding(RecoveryStreamKind.COST, 2, "lucy-cost-journal"),
    }
    assert initialize_pair(client, **arguments) == {
        "authority_created": True,
        "cost_created": True,
    }
    assert initialize_pair(client, **arguments) == {
        "authority_created": False,
        "cost_created": False,
    }
    assert len(client.items) == 2


def test_pair_rejects_cross_table_or_cross_manifest_binding() -> None:
    authority = _binding(RecoveryStreamKind.AUTHORITY, 1, "wrong-table")
    cost = _binding(RecoveryStreamKind.COST, 2, "lucy-cost-journal")
    with pytest.raises(ValueError, match="deployed table"):
        initialize_pair(
            FakeDynamo(),
            account_id=ACCOUNT,
            region="us-east-1",
            authority_table="lucy-authority-journal",
            authority_binding=authority,
            cost_table="lucy-cost-journal",
            cost_binding=cost,
        )

    changed = cost.model_copy(update={"binding_manifest_digest": "b" * 64})
    with pytest.raises(ValueError, match="share one manifest"):
        initialize_pair(
            FakeDynamo(),
            account_id=ACCOUNT,
            region="us-east-1",
            authority_table="wrong-table",
            authority_binding=authority,
            cost_table="lucy-cost-journal",
            cost_binding=changed,
        )


def _value(item: dict[str, object], name: str) -> str:
    attribute = item[name]
    assert isinstance(attribute, dict)
    value = attribute["S"]
    assert isinstance(value, str)
    return value


def _conditional_failure() -> NoReturn:
    raise ClientError(
        {"Error": {"Code": "ConditionalCheckFailedException", "Message": "conditional"}},
        "PutItem",
    )
