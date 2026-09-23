"""Exercise the packaged M4 writer handler inside the Lambda Python 3.12 runtime image.

Run from the unzipped artifact, with nothing else on the path:

    docker run --rm --entrypoint /var/lang/bin/python3 \
      -v <unzipped artifact>:/var/task:ro -v <this file>:/smoke.py:ro \
      public.ecr.aws/lambda/python:3.12 /smoke.py

It proves the artifact's own modules and locked wheels load and behave on the target runtime:
configuration is checked against its digest, a signed transition installs, an identical retry
succeeds without a second write, and malformed or forged requests are refused with a reason code.
No AWS call is made; the table is an in-memory stand-in that enforces the conditional write.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lucy.shared_execution import anchor_writer_lambda
from lucy.shared_execution.recovery_anchor import RecoveryAnchorIdentity
from lucy.shared_execution.recovery_anchor_commissioning import build_quarantined_bootstrap

ROOT_KEY_ID = "tiamat-recovery-root.smoke.1"


class ConditionalTable:
    def __init__(self) -> None:
        self.items: dict[str, dict[str, Any]] = {}
        self.puts = 0

    def get_item(self, **kwargs: Any) -> dict[str, Any]:
        item = self.items.get(kwargs["Key"]["anchor_key"]["S"])
        return {} if item is None else {"Item": item}

    def put_item(self, **kwargs: Any) -> dict[str, Any]:
        from botocore.exceptions import ClientError

        self.puts += 1
        item = kwargs["Item"]
        key = item["anchor_key"]["S"]
        current = self.items.get(key)
        if kwargs["ConditionExpression"] == "attribute_not_exists(#anchor_key)":
            holds = current is None
        else:
            values = kwargs["ExpressionAttributeValues"]
            holds = current is not None and (
                current["transition_sha256"]["S"] == values[":expected_digest"]["S"]
            )
        if not holds:
            raise ClientError(
                {"Error": {"Code": "ConditionalCheckFailedException", "Message": "no"}}, "PutItem"
            )
        self.items[key] = item
        return {}


def main() -> int:
    identity = RecoveryAnchorIdentity("smoke", uuid4(), uuid4())
    anchor_key = f"ENV#{identity.environment}#LEDGER#{identity.ledger_id}"
    root = Ed25519PrivateKey.generate()
    raw_root = root.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    roots = json.dumps(
        {
            anchor_key: {
                "root_key_id": ROOT_KEY_ID,
                "root_public_key_b64": base64.b64encode(raw_root).decode(),
                "root_public_key_sha256": hashlib.sha256(raw_root).hexdigest(),
            }
        }
    )
    environment = {
        "TIAMAT_RECOVERY_ANCHOR_TABLE": "smoke-anchor",
        "AWS_REGION": "us-east-1",
        "TIAMAT_ANCHOR_WRITER_ROOTS": roots,
        "TIAMAT_ANCHOR_WRITER_ROOTS_SHA256": hashlib.sha256(roots.encode()).hexdigest(),
    }
    results: dict[str, Any] = {"python": sys.version.split()[0]}

    try:
        anchor_writer_lambda.writer_from_environment(
            {**environment, "TIAMAT_ANCHOR_WRITER_ROOTS_SHA256": "0" * 64},
            client=ConditionalTable(),
        )
        results["mismatched_roots_digest"] = "accepted"
    except ValueError:
        results["mismatched_roots_digest"] = "refused"

    table = ConditionalTable()
    anchor_writer_lambda._writer = anchor_writer_lambda.writer_from_environment(
        environment, client=table
    )
    artifacts, _ = build_quarantined_bootstrap(
        identity=identity,
        root_key_id=ROOT_KEY_ID,
        root_private_key=root,
        witness_key_id="tiamat-recovery-witness.smoke.1",
        witness_private_key=Ed25519PrivateKey.generate(),
        checkpoint={
            "environment": identity.environment,
            "ledger_id": str(identity.ledger_id),
            "storage_epoch": str(identity.storage_epoch),
            "recovery_generation": 1,
            "release_inventory": {"state": "not_installed"},
            "release_heads": [],
            "settlement_position": [],
        },
        now=datetime.now(UTC) - timedelta(minutes=1),
    )
    event = {
        "anchor_key": anchor_key,
        "transition_jws_b64": base64.b64encode(artifacts.transition_jws).decode(),
        "witness_jws_b64": base64.b64encode(artifacts.witness_jws).decode(),
        "inventory_jws_b64": base64.b64encode(artifacts.inventory_jws).decode(),
    }
    results["install"] = anchor_writer_lambda.handler(event, None)
    results["retry"] = anchor_writer_lambda.handler(event, None)
    results["puts"] = table.puts
    results["malformed"] = anchor_writer_lambda.handler({"anchor_key": anchor_key}, None)
    forged = dict(event)
    altered = artifacts.transition_jws[:-4] + b"AAAA"
    forged["transition_jws_b64"] = base64.b64encode(altered).decode()
    results["forged"] = anchor_writer_lambda.handler(forged, None)
    results["database_driver_loaded"] = any(name.startswith("psycopg") for name in sys.modules)

    expected = (
        results["mismatched_roots_digest"] == "refused"
        and results["install"]["status"] == "installed"
        and results["install"]["transition_sha256"] == artifacts.transition_sha256
        and results["retry"]["status"] == "already_installed"
        and results["puts"] == 1
        and results["malformed"]
        == {"status": "refused", "reason": "recovery_anchor_writer_request_invalid"}
        and results["forged"]["status"] == "refused"
        and results["database_driver_loaded"] is False
    )
    results["passed"] = expected
    print(json.dumps(results, sort_keys=True))
    return 0 if expected else 1


if __name__ == "__main__":
    raise SystemExit(main())
