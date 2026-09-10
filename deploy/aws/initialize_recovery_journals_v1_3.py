"""Initialize the two R1 recovery journal heads without overwrite authority.

Run this once with the human security-administrator identity after the additive
recovery stack is deployed. Inputs and output are content-free.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

import boto3  # type: ignore[import-untyped]
from pydantic import ValidationError

from lucy.recovery_journal import RecoveryStreamBindingV1, RecoveryStreamKind
from lucy.recovery_journal_aws import DynamoRecoveryClient, initialize_recovery_head


def initialize_pair(
    client: DynamoRecoveryClient,
    *,
    account_id: str,
    region: str,
    authority_table: str,
    authority_binding: RecoveryStreamBindingV1,
    cost_table: str,
    cost_binding: RecoveryStreamBindingV1,
) -> dict[str, bool]:
    """Validate and create both genesis heads; exact reruns are safe."""

    if re.fullmatch(r"\d{12}", account_id) is None or region != "us-east-1":
        raise ValueError("recovery deployment account or region is invalid")
    if authority_binding.stream_kind is not RecoveryStreamKind.AUTHORITY:
        raise ValueError("authority binding has the wrong stream kind")
    if cost_binding.stream_kind is not RecoveryStreamKind.COST:
        raise ValueError("cost binding has the wrong stream kind")
    if authority_binding.stream_id == cost_binding.stream_id:
        raise ValueError("authority and cost streams must be distinct")
    if authority_binding.binding_manifest_digest != cost_binding.binding_manifest_digest:
        raise ValueError("authority and cost bindings must share one manifest")

    expected_stores = {
        authority_binding.independent_store_id: authority_table,
        cost_binding.independent_store_id: cost_table,
    }
    for store_arn, table_name in expected_stores.items():
        expected = f"arn:aws:dynamodb:{region}:{account_id}:table/{table_name}"
        if store_arn != expected:
            raise ValueError("recovery binding does not match its deployed table")

    return {
        "authority_created": initialize_recovery_head(
            client, table_name=authority_table, binding=authority_binding
        ),
        "cost_created": initialize_recovery_head(
            client, table_name=cost_table, binding=cost_binding
        ),
    }


def _load_binding(path: Path) -> RecoveryStreamBindingV1:
    try:
        return RecoveryStreamBindingV1.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValidationError) as exc:
        raise ValueError(f"invalid recovery binding file: {path}") from exc


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account-id", required=True)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--authority-table", required=True)
    parser.add_argument("--authority-binding", type=Path, required=True)
    parser.add_argument("--cost-table", required=True)
    parser.add_argument("--cost-binding", type=Path, required=True)
    arguments = parser.parse_args()

    client: Any = boto3.client("dynamodb", region_name=arguments.region)
    result = initialize_pair(
        client,
        account_id=arguments.account_id,
        region=arguments.region,
        authority_table=arguments.authority_table,
        authority_binding=_load_binding(arguments.authority_binding),
        cost_table=arguments.cost_table,
        cost_binding=_load_binding(arguments.cost_binding),
    )
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
