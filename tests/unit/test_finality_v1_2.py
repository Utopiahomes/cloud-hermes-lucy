from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest
from pydantic import ValidationError

import lucy.finality as finality
from lucy.contracts.security_v1_2 import DeletionRecoveryInventoryV1
from lucy.finality import AwsRecoveryInventoryCollector

NOW = datetime(2026, 9, 2, 19, 0, tzinfo=UTC)
OPERATION_ID = UUID("11111111-1111-4111-8111-111111111111")
TABLE = "cloud-lucy-wrapped-keys"
TABLE_ARN = f"arn:aws:dynamodb:us-east-1:123456789012:table/{TABLE}"


class FakeDynamoDb:
    def __init__(self, *, exceptional: bool = False) -> None:
        self.exceptional = exceptional
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def describe_table(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("describe_table", kwargs))
        name = kwargs["TableName"]
        return {
            "Table": {
                "TableName": name,
                "TableArn": f"arn:aws:dynamodb:us-east-1:123456789012:table/{name}",
                "CreationDateTime": NOW - timedelta(days=100),
                "TableStatus": "ACTIVE",
                "StreamSpecification": {"StreamEnabled": False},
                "Replicas": [],
            }
        }

    def describe_continuous_backups(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("describe_continuous_backups", kwargs))
        return {
            "ContinuousBackupsDescription": {
                "PointInTimeRecoveryDescription": {
                    "PointInTimeRecoveryStatus": "ENABLED",
                    "RecoveryPeriodInDays": 30,
                    "EarliestRestorableDateTime": NOW - timedelta(days=29),
                    "LatestRestorableDateTime": NOW - timedelta(minutes=5),
                }
            }
        }

    def list_tables(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("list_tables", kwargs))
        names = [TABLE]
        if self.exceptional:
            names.append("cloud-lucy-quarantine-test")
        return {"TableNames": names}

    def list_backups(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("list_backups", kwargs))
        if not self.exceptional:
            return {"BackupSummaries": []}
        return {
            "BackupSummaries": [
                {
                    "TableName": TABLE,
                    "BackupStatus": "AVAILABLE",
                    "BackupCreationDateTime": NOW - timedelta(days=2),
                    "BackupExpiryDateTime": NOW + timedelta(days=5),
                }
            ]
        }

    def list_exports(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("list_exports", kwargs))
        return {"ExportSummaries": []}

    def list_imports(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("list_imports", kwargs))
        return {"ImportSummaryList": []}

    def list_global_tables(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("list_global_tables", kwargs))
        return {"GlobalTables": []}

    def list_tags_of_resource(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("list_tags_of_resource", kwargs))
        return {"Tags": [{"Key": "lucy:recovery-boundary", "Value": "quarantine"}]}


class FakeBackup:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def list_recovery_points_by_resource(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        return {"RecoveryPoints": []}


def test_finality_collector_reports_facts_and_never_reads_an_item() -> None:
    dynamodb = FakeDynamoDb()
    backup = FakeBackup()
    inventory = AwsRecoveryInventoryCollector(
        dynamodb,
        backup,
        table_name=TABLE,
        quarantine_prefix="cloud-lucy-quarantine-",
        clock=lambda: NOW,
    ).collect(OPERATION_ID)

    assert inventory.pitr_status == "ENABLED"
    assert inventory.pitr_recovery_period_days == 30
    assert inventory.on_demand_backup_count == 0
    assert inventory.quarantine_table_count == 0
    assert inventory.exceptional_earliest_restorable_at is None
    assert inventory.exceptional_latest_restorable_at is None
    assert len(inventory.metadata_inventory_digest) == 64
    assert not {
        "get_item",
        "scan",
        "query",
        "batch_get_item",
        "restore_table_to_point_in_time",
    } & {name for name, _ in dynamodb.calls}
    assert backup.calls == [{"ResourceArn": TABLE_ARN}]


def test_exceptional_copy_inventory_is_conservative_and_indefinite() -> None:
    inventory = AwsRecoveryInventoryCollector(
        FakeDynamoDb(exceptional=True),
        FakeBackup(),
        table_name=TABLE,
        quarantine_prefix="cloud-lucy-quarantine-",
        clock=lambda: NOW,
    ).collect(OPERATION_ID)
    assert inventory.on_demand_backup_count == 1
    assert inventory.quarantine_table_count == 1
    assert inventory.exceptional_earliest_restorable_at == NOW - timedelta(days=100)
    assert inventory.exceptional_latest_restorable_at is None


def test_finality_inventory_rejects_incomplete_enabled_pitr() -> None:
    with pytest.raises(ValidationError, match="actual recovery interval"):
        DeletionRecoveryInventoryV1(
            operation_id=OPERATION_ID,
            metadata_observed_at=NOW,
            pitr_status="ENABLED",
            pitr_recovery_period_days=30,
            on_demand_backup_count=0,
            aws_backup_recovery_point_count=0,
            export_count=0,
            import_count=0,
            global_replica_count=0,
            quarantine_table_count=0,
            stream_enabled=False,
            metadata_inventory_digest="a" * 64,
        )


def test_scheduled_sentinel_never_contacts_aws_or_postgresql(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(finality.boto3, "client", lambda *_a, **_k: pytest.fail("AWS called"))
    monkeypatch.setattr(
        finality,
        "create_session_factory",
        lambda *_a, **_k: pytest.fail("PostgreSQL called"),
    )
    assert finality.main(["--scheduled-sentinel"]) == 0
    assert "no operation authorized" in capsys.readouterr().out


def test_finality_output_explains_count_without_changing_verdict(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    dynamodb = FakeDynamoDb(exceptional=True)
    monkeypatch.setattr(
        finality.boto3, "client",
        lambda name, **_kw: dynamodb if name == "dynamodb" else FakeBackup(),
    )
    for key, value in {
        "LUCY_SERVICE_MODE": "finality", "AWS_REGION": "us-east-1",
        "LUCY_AWS_WRAPPED_KEY_TABLE": TABLE,
        "LUCY_FINALITY_QUARANTINE_TABLE_PREFIX": "cloud-lucy-quarantine-",
        "LUCY_DATABASE_URL": "test-only",
    }.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(finality, "record_finality_inventory", lambda *_a: "EXTENDED")
    assert finality.main(["--operation-id", str(OPERATION_ID)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "EXTENDED"
    assert result["recoverable_copy_count"] == 2
    assert sum(result["recovery_copy_counts"].values()) == 2
    assert result["recovery_copy_counts"]["on_demand_backups"] == 1
    assert result["recovery_copy_counts"]["quarantine_tables"] == 1
