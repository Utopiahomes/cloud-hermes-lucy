"""Prove, with real credentials, that this principal cannot write the recovery anchor table.

Run it as each principal that must be refused - the recovery coordinator and the runtime from
their Render services, and an administrator from a workstation. It reports who it ran as, then
attempts every kind of item write against a disposable key that no ledger uses, and reports
whether each was denied. It never touches a real ledger's key, and every write it attempts is
expected to fail; one that succeeds is reported, not hidden.

Output is content-free JSON. Exit status is 0 only if every write was denied.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from typing import Any
from uuid import uuid4

import boto3  # type: ignore[import-untyped]
from botocore.exceptions import ClientError  # type: ignore[import-untyped]

DENIED = {"AccessDeniedException", "AccessDenied", "UnauthorizedOperation"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--table", required=True)
    parser.add_argument("--environment", required=True)
    parser.add_argument("--region", default="us-east-1")
    args = parser.parse_args()

    key = f"ENV#{args.environment}#LEDGER#boundary-probe-{uuid4()}"
    item = {"anchor_key": {"S": key}, "probe": {"S": "must-not-be-written"}}
    dynamodb = boto3.client("dynamodb", region_name=args.region)
    identity = boto3.client("sts", region_name=args.region).get_caller_identity()["Arn"]
    attempts: dict[str, Callable[[], Any]] = {
        "PutItem": lambda: dynamodb.put_item(TableName=args.table, Item=item),
        "UpdateItem": lambda: dynamodb.update_item(
            TableName=args.table,
            Key={"anchor_key": {"S": key}},
            UpdateExpression="SET probe = :v",
            ExpressionAttributeValues={":v": {"S": "must-not-be-written"}},
        ),
        "DeleteItem": lambda: dynamodb.delete_item(
            TableName=args.table, Key={"anchor_key": {"S": key}}
        ),
        "BatchWriteItem": lambda: dynamodb.batch_write_item(
            RequestItems={args.table: [{"PutRequest": {"Item": item}}]}
        ),
        "TransactWriteItems": lambda: dynamodb.transact_write_items(
            TransactItems=[{"Put": {"TableName": args.table, "Item": item}}]
        ),
        "PartiQLInsert": lambda: dynamodb.execute_statement(
            Statement=f"INSERT INTO \"{args.table}\" VALUE {{'anchor_key': ?, 'probe': ?}}",
            Parameters=[{"S": key}, {"S": "must-not-be-written"}],
        ),
    }
    results: dict[str, str] = {}
    for name, attempt in attempts.items():
        try:
            attempt()
            results[name] = "WRITTEN"
        except ClientError as exc:
            code = str(exc.response.get("Error", {}).get("Code", ""))
            results[name] = "denied" if code in DENIED else f"failed:{code}"
    all_denied = all(outcome == "denied" for outcome in results.values())
    print(
        json.dumps(
            {"caller": identity, "probe_key": key, "results": results, "all_denied": all_denied},
            sort_keys=True,
        )
    )
    return 0 if all_denied else 1


if __name__ == "__main__":
    sys.exit(main())
