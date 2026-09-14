"""Operator-triggered, metadata-only deletion-finality verification.

The utility reports observed AWS recovery facts. It never decides that deletion
is final: the security-definer PostgreSQL function combines these facts with
the authoritative deletion timestamp and derives the monotonic verdict.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from collections.abc import Callable, Iterable, Mapping
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import boto3  # type: ignore[import-untyped]
from botocore.exceptions import BotoCoreError, ClientError  # type: ignore[import-untyped]
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from lucy.contracts.canonical import canonical_json_bytes
from lucy.contracts.security_v1_2 import DeletionRecoveryInventoryV1
from lucy.db import create_session_factory

_TABLE_NAME = re.compile(r"[A-Za-z0-9_.-]{3,255}")
_QUARANTINE_PREFIX = re.compile(r"[A-Za-z0-9_.-]{3,200}-quarantine-")
_MAX_PAGES = 1_000


class FinalityInventoryError(RuntimeError):
    """Content-free finality inventory failure."""


class _RecoveryWindow:
    def __init__(self) -> None:
        self._starts: list[datetime] = []
        self._finite_ends: list[datetime] = []
        self._has_indefinite_copy = False

    def add(self, start: datetime | None, end: datetime | None) -> None:
        if start is not None:
            self._starts.append(_aware(start))
        if end is None:
            self._has_indefinite_copy = True
        else:
            self._finite_ends.append(_aware(end))

    @property
    def earliest(self) -> datetime | None:
        return min(self._starts) if self._starts else None

    @property
    def latest(self) -> datetime | None:
        if self._has_indefinite_copy:
            return None
        return max(self._finite_ends) if self._finite_ends else None


class AwsRecoveryInventoryCollector:
    """Collect bounded recovery metadata without reading a DynamoDB item."""

    def __init__(
        self,
        dynamodb: Any,
        backup: Any,
        *,
        table_name: str,
        quarantine_prefix: str,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if _TABLE_NAME.fullmatch(table_name) is None:
            raise ValueError("wrapped-key table name is invalid")
        if (
            _QUARANTINE_PREFIX.fullmatch(quarantine_prefix) is None
            or not quarantine_prefix.startswith(table_name.rsplit("-wrapped-keys", 1)[0])
        ):
            raise ValueError("quarantine table prefix is invalid")
        self._dynamodb = dynamodb
        self._backup = backup
        self._table_name = table_name
        self._quarantine_prefix = quarantine_prefix
        self._clock = clock or (lambda: datetime.now(UTC))

    def collect(self, operation_id: UUID) -> DeletionRecoveryInventoryV1:
        observed_at = _aware(self._clock())
        source = self._dynamodb.describe_table(TableName=self._table_name)["Table"]
        table_arn = _required_string(source, "TableArn")
        pitr = self._dynamodb.describe_continuous_backups(
            TableName=self._table_name
        )["ContinuousBackupsDescription"]["PointInTimeRecoveryDescription"]
        pitr_status = str(pitr.get("PointInTimeRecoveryStatus", "DISABLED"))
        pitr_enabled = pitr_status == "ENABLED"

        table_names = self._table_names()
        quarantine_names = tuple(
            sorted(name for name in table_names if name.startswith(self._quarantine_prefix))
        )
        quarantine_tables = [
            self._dynamodb.describe_table(TableName=name)["Table"]
            for name in quarantine_names
        ]
        quarantine_tags = [
            self._dynamodb.list_tags_of_resource(
                ResourceArn=_required_string(table, "TableArn")
            ).get("Tags", [])
            for table in quarantine_tables
        ]
        relevant_arns = {table_arn}
        relevant_arns.update(
            _required_string(table, "TableArn") for table in quarantine_tables
        )
        relevant_names = {self._table_name, *quarantine_names}

        backups = tuple(
            item
            for item in self._list_dynamodb("list_backups", "BackupSummaries")
            if item.get("TableName") in relevant_names
            and item.get("BackupStatus") not in {"DELETED", "FAILED"}
        )
        exports = tuple(
            item
            for item in self._list_dynamodb("list_exports", "ExportSummaries")
            if item.get("TableArn") in relevant_arns
            and item.get("ExportStatus") not in {"FAILED", "CANCELLED"}
        )
        imports = tuple(
            item
            for item in self._list_dynamodb("list_imports", "ImportSummaryList")
            if item.get("TableArn") in relevant_arns
            and item.get("ImportStatus") not in {"FAILED", "CANCELLED"}
        )
        global_tables = tuple(
            item
            for item in self._list_dynamodb("list_global_tables", "GlobalTables")
            if item.get("GlobalTableName") in relevant_names
        )
        recovery_points: list[Mapping[str, Any]] = []
        for arn in sorted(relevant_arns):
            recovery_points.extend(self._aws_backup_recovery_points(arn))

        replicas = sum(len(item.get("ReplicationGroup", ())) for item in global_tables)
        replicas += sum(len(table.get("Replicas", ())) for table in [source, *quarantine_tables])
        stream_enabled = any(
            bool(table.get("StreamSpecification", {}).get("StreamEnabled", False))
            for table in [source, *quarantine_tables]
        )

        window = _RecoveryWindow()
        for item in backups:
            window.add(
                _optional_datetime(item.get("BackupCreationDateTime")),
                _optional_datetime(item.get("BackupExpiryDateTime")),
            )
        for item in recovery_points:
            lifecycle = item.get("CalculatedLifecycle", {})
            window.add(
                _optional_datetime(item.get("CreationDate")),
                _optional_datetime(lifecycle.get("DeleteAt")),
            )
        for item in exports:
            window.add(_optional_datetime(item.get("ExportTime")), None)
        for item in imports:
            window.add(_optional_datetime(item.get("ImportStartTime")), None)
        for table in quarantine_tables:
            window.add(_optional_datetime(table.get("CreationDateTime")), None)
        if replicas or stream_enabled:
            window.add(observed_at, None)

        normalized = {
            "source": _table_summary(source),
            "pitr": _json_safe(pitr),
            "backups": [_json_safe(item) for item in backups],
            "aws_backup_recovery_points": [_json_safe(item) for item in recovery_points],
            "exports": [_json_safe(item) for item in exports],
            "imports": [_json_safe(item) for item in imports],
            "global_tables": [_json_safe(item) for item in global_tables],
            "quarantine_tables": [
                {"table": _table_summary(table), "tags": _json_safe(tags)}
                for table, tags in zip(quarantine_tables, quarantine_tags, strict=True)
            ],
        }
        inventory_digest = hashlib.sha256(
            b"LUCY-DELETION-RECOVERY-INVENTORY-V1\0" + canonical_json_bytes(normalized)
        ).hexdigest()
        return DeletionRecoveryInventoryV1(
            operation_id=operation_id,
            metadata_observed_at=observed_at,
            pitr_status="ENABLED" if pitr_enabled else "DISABLED",
            pitr_recovery_period_days=(
                int(pitr["RecoveryPeriodInDays"]) if pitr_enabled else None
            ),
            pitr_earliest_restorable_at=(
                _aware(pitr["EarliestRestorableDateTime"]) if pitr_enabled else None
            ),
            pitr_latest_restorable_at=(
                _aware(pitr["LatestRestorableDateTime"]) if pitr_enabled else None
            ),
            on_demand_backup_count=len(backups),
            aws_backup_recovery_point_count=len(recovery_points),
            export_count=len(exports),
            import_count=len(imports),
            global_replica_count=replicas,
            quarantine_table_count=len(quarantine_tables),
            stream_enabled=stream_enabled,
            exceptional_earliest_restorable_at=window.earliest,
            exceptional_latest_restorable_at=window.latest,
            metadata_inventory_digest=inventory_digest,
        )

    def _table_names(self) -> tuple[str, ...]:
        return tuple(
            str(item)
            for item in self._list_dynamodb("list_tables", "TableNames")
        )

    def _list_dynamodb(self, method: str, result_key: str) -> Iterable[Any]:
        token_names = {
            "list_tables": ("ExclusiveStartTableName", "LastEvaluatedTableName"),
            "list_backups": ("ExclusiveStartBackupArn", "LastEvaluatedBackupArn"),
            "list_exports": ("NextToken", "NextToken"),
            "list_imports": ("NextToken", "NextToken"),
            "list_global_tables": (
                "ExclusiveStartGlobalTableName",
                "LastEvaluatedGlobalTableName",
            ),
        }
        try:
            token_name, response_token = token_names[method]
        except KeyError as exc:
            raise ValueError("unsupported DynamoDB inventory operation") from exc
        token: str | None = None
        seen: set[str] = set()
        for _ in range(_MAX_PAGES):
            kwargs = {token_name: token} if token is not None else {}
            response = getattr(self._dynamodb, method)(**kwargs)
            values = response.get(result_key, ())
            if not isinstance(values, list):
                raise FinalityInventoryError("AWS inventory response is invalid")
            yield from values
            next_token = response.get(response_token)
            if next_token is None:
                return
            if not isinstance(next_token, str) or next_token in seen:
                raise FinalityInventoryError("AWS inventory pagination is invalid")
            seen.add(next_token)
            token = next_token
        raise FinalityInventoryError("AWS inventory exceeds the bounded page limit")

    def _aws_backup_recovery_points(self, resource_arn: str) -> list[Mapping[str, Any]]:
        results: list[Mapping[str, Any]] = []
        token: str | None = None
        seen: set[str] = set()
        for _ in range(_MAX_PAGES):
            kwargs: dict[str, str] = {"ResourceArn": resource_arn}
            if token is not None:
                kwargs["NextToken"] = token
            response = self._backup.list_recovery_points_by_resource(**kwargs)
            values = response.get("RecoveryPoints", ())
            if not isinstance(values, list):
                raise FinalityInventoryError("AWS Backup inventory response is invalid")
            results.extend(
                item
                for item in values
                if isinstance(item, Mapping)
                and item.get("Status") not in {"DELETED", "EXPIRED", "FAILED"}
            )
            next_token = response.get("NextToken")
            if next_token is None:
                return results
            if not isinstance(next_token, str) or next_token in seen:
                raise FinalityInventoryError("AWS Backup pagination is invalid")
            seen.add(next_token)
            token = next_token
        raise FinalityInventoryError("AWS Backup inventory exceeds the bounded page limit")


def record_finality_inventory(
    operation_id: UUID,
    inventory: DeletionRecoveryInventoryV1,
    database_url: str,
) -> str:
    if inventory.operation_id != operation_id:
        raise ValueError("finality operation binding differs")
    sessions = create_session_factory(database_url)
    with sessions.begin() as session:
        result = session.scalar(
            text(
                "SELECT lucy.record_scoped_finality_inventory_v2("
                ":operation_id,CAST(:metadata AS jsonb))"
            ),
            {
                "operation_id": operation_id,
                "metadata": json.dumps(inventory.model_dump(mode="json"), separators=(",", ":")),
            },
        )
    if not isinstance(result, Mapping) or result.get("status") not in {
        "EXTENDED",
        "VERIFIED",
    }:
        raise FinalityInventoryError("database returned an invalid finality state")
    return str(result["status"])


def _required_environment(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise FinalityInventoryError("finality utility configuration is incomplete")
    return value


def _required_string(value: Mapping[str, Any], name: str) -> str:
    result = value.get(name)
    if not isinstance(result, str) or not result:
        raise FinalityInventoryError("AWS inventory response is invalid")
    return result


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise FinalityInventoryError("AWS inventory timestamp is invalid")
    return value.astimezone(UTC)


def _optional_datetime(value: object) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, datetime):
        raise FinalityInventoryError("AWS inventory timestamp is invalid")
    return _aware(value)


def _json_safe(value: object) -> Any:
    if isinstance(value, datetime):
        return _aware(value)
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return str(value)


def _table_summary(table: Mapping[str, Any]) -> Mapping[str, Any]:
    return {
        "table_arn": table.get("TableArn"),
        "table_name": table.get("TableName"),
        "creation_date_time": _json_safe(table.get("CreationDateTime")),
        "table_status": table.get("TableStatus"),
        "stream_specification": _json_safe(table.get("StreamSpecification", {})),
        "replicas": _json_safe(table.get("Replicas", [])),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Cloud Lucy deletion finality utility")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--scheduled-sentinel", action="store_true")
    group.add_argument("--operation-id", type=UUID)
    args = parser.parse_args(argv)
    if args.scheduled_sentinel:
        print("Lucy finality sentinel: no operation authorized")
        return 0
    try:
        if os.getenv("LUCY_SERVICE_MODE") != "finality":
            raise FinalityInventoryError("finality utility identity is invalid")
        region = _required_environment("AWS_REGION")
        collector = AwsRecoveryInventoryCollector(
            boto3.client("dynamodb", region_name=region),
            boto3.client("backup", region_name=region),
            table_name=_required_environment("LUCY_AWS_WRAPPED_KEY_TABLE"),
            quarantine_prefix=_required_environment("LUCY_FINALITY_QUARANTINE_TABLE_PREFIX"),
        )
        operation_id = args.operation_id
        if operation_id is None:
            raise FinalityInventoryError("finality operation is missing")
        inventory = collector.collect(operation_id)
        status = record_finality_inventory(
            operation_id,
            inventory,
            _required_environment("LUCY_DATABASE_URL"),
        )
        print(
            json.dumps(
                {
                    "operation_id": str(operation_id),
                    "status": status,
                    "metadata_inventory_digest": inventory.metadata_inventory_digest,
                    "recovery_copy_counts": {
                        "on_demand_backups": inventory.on_demand_backup_count,
                        "aws_backup_recovery_points": inventory.aws_backup_recovery_point_count,
                        "exports": inventory.export_count,
                        "imports": inventory.import_count,
                        "global_replicas": inventory.global_replica_count,
                        "quarantine_tables": inventory.quarantine_table_count,
                        "streams": int(inventory.stream_enabled),
                    },
                    "recoverable_copy_count": (
                        inventory.on_demand_backup_count
                        + inventory.aws_backup_recovery_point_count
                        + inventory.export_count
                        + inventory.import_count
                        + inventory.global_replica_count
                        + inventory.quarantine_table_count
                        + int(inventory.stream_enabled)
                    ),
                },
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 0
    except (
        BotoCoreError,
        ClientError,
        FinalityInventoryError,
        KeyError,
        SQLAlchemyError,
        TypeError,
        ValueError,
    ):
        print("Lucy finality verification failed closed")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
