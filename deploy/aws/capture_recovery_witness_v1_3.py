"""Capture an independently retained, exact two-stream R1 recovery witness."""

from __future__ import annotations

import argparse
import json
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import boto3  # type: ignore[import-untyped]
from pydantic import ValidationError

from lucy.contracts.canonical import canonical_sha256
from lucy.recovery_journal import (
    RecoveryJournalError,
    RecoveryStreamBindingV1,
    RecoveryStreamKind,
)
from lucy.recovery_journal_aws import AwsDynamoRecoveryJournal, DynamoRecoveryClient

REGION = "us-east-1"


class RecoveryWitnessError(RuntimeError):
    """The exact two-stream witness could not be established."""


def _table_name(binding: RecoveryStreamBindingV1, account_id: str) -> str:
    prefix = f"arn:aws:dynamodb:{REGION}:{account_id}:table/"
    if not binding.independent_store_id.startswith(prefix):
        raise RecoveryWitnessError("recovery binding store is outside the target account")
    table = binding.independent_store_id.removeprefix(prefix)
    if not table or "/" in table:
        raise RecoveryWitnessError("recovery binding table name is invalid")
    return table


def capture(
    *,
    authority_binding: RecoveryStreamBindingV1,
    cost_binding: RecoveryStreamBindingV1,
    account_id: str,
    identity: Mapping[str, Any],
    client: DynamoRecoveryClient,
    captured_at: datetime,
) -> dict[str, Any]:
    if (
        identity.get("Account") != account_id
        or authority_binding.stream_kind is not RecoveryStreamKind.AUTHORITY
        or cost_binding.stream_kind is not RecoveryStreamKind.COST
        or authority_binding.stream_id == cost_binding.stream_id
        or authority_binding.independent_store_id == cost_binding.independent_store_id
        or authority_binding.binding_manifest_digest
        != cost_binding.binding_manifest_digest
        or captured_at.tzinfo is None
        or captured_at.utcoffset() is None
    ):
        raise RecoveryWitnessError("two-stream witness boundary is invalid")
    authority = AwsDynamoRecoveryJournal.from_configuration(
        client,
        region=REGION,
        account_id=account_id,
        table_name=_table_name(authority_binding, account_id),
        binding=authority_binding,
    ).head()
    cost = AwsDynamoRecoveryJournal.from_configuration(
        client,
        region=REGION,
        account_id=account_id,
        table_name=_table_name(cost_binding, account_id),
        binding=cost_binding,
    ).head()
    body: dict[str, Any] = {
        "contract": "lucy.recovery-witness-bundle.v1",
        "captured_at": captured_at.astimezone(UTC).isoformat(),
        "aws_account_id": account_id,
        "aws_region": REGION,
        "binding_manifest_digest": authority_binding.binding_manifest_digest,
        "authority_witness": authority.model_dump(mode="json"),
        "cost_witness": cost.model_dump(mode="json"),
        "read_method": "dynamodb_strongly_consistent_exact_get",
    }
    return body | {
        "bundle_digest": canonical_sha256(
            body, prefix=b"LUCY-RECOVERY-WITNESS-BUNDLE-V1\0"
        )
    }


def _binding(path: Path) -> RecoveryStreamBindingV1:
    try:
        return RecoveryStreamBindingV1.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValidationError, ValueError) as exc:
        raise RecoveryWitnessError("recovery binding file is invalid") from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--account-id", required=True)
    parser.add_argument("--authority-binding", required=True, type=Path)
    parser.add_argument("--cost-binding", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.output.exists():
        raise FileExistsError(f"refusing to overwrite recovery witness: {args.output}")
    if not args.output.parent.is_dir():
        raise FileNotFoundError("recovery witness output directory does not exist")
    session: Any = boto3.Session(profile_name=args.profile, region_name=REGION)
    identity = session.client("sts").get_caller_identity()
    try:
        report = capture(
            authority_binding=_binding(args.authority_binding),
            cost_binding=_binding(args.cost_binding),
            account_id=args.account_id,
            identity=identity,
            client=session.client("dynamodb"),
            captured_at=datetime.now(UTC),
        )
    except RecoveryJournalError as exc:
        raise RecoveryWitnessError("recovery journal head is unavailable") from exc
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        "captured exact authority/cost recovery witness "
        f"sha256={report['bundle_digest']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
