from __future__ import annotations

import pytest

import deploy.postgres.rebind_executors_cloud_v1_2 as rebind
from deploy.postgres.rebind_executors_cloud_v1_2 import (
    AUTHORIZATION,
    RebindConfig,
    RebindError,
)


class _Result:
    def __init__(
        self,
        *,
        one: tuple[object, ...] | None = None,
        rows: list[tuple[object, ...]] | None = None,
        rowcount: int = -1,
    ) -> None:
        self._one = one
        self._rows = [] if rows is None else rows
        self.rowcount = rowcount

    def fetchone(self) -> tuple[object, ...] | None:
        return self._one

    def fetchall(self) -> list[tuple[object, ...]]:
        return self._rows


class _Connection:
    def __init__(self, config: RebindConfig, *, unresolved: int = 0) -> None:
        self.config = config
        self.unresolved = unresolved
        self.statements: list[str] = []
        self.bindings = rebind._expected_rows(config, target=False)

    def __enter__(self) -> _Connection:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, statement: str, parameters: object = None) -> _Result:
        normalized = " ".join(statement.split())
        self.statements.append(normalized)
        if normalized.startswith("SET LOCAL") or "pg_advisory_xact_lock" in normalized:
            return _Result()
        if "FROM pg_stat_ssl" in normalized:
            return _Result(one=(True,))
        if "FROM lucy.runtime_admission" in normalized:
            return _Result(one=("quarantined",))
        if "FROM lucy.security_contract_epochs" in normalized:
            return _Result(
                one=(
                    self.config.storage_epoch,
                    self.config.registry_epoch,
                    self.config.key_epoch,
                )
            )
        if "FROM lucy.executor_bindings_v1" in normalized:
            return _Result(rows=list(self.bindings))
        if "FROM lucy.operations" in normalized:
            return _Result(one=(self.unresolved,))
        if normalized.startswith("UPDATE lucy.executor_bindings_v1"):
            assert isinstance(parameters, tuple)
            version, action = parameters
            self.bindings = [
                (
                    row[0],
                    row[1],
                    row[2],
                    version if row[0] == action else row[3],
                    row[4],
                    row[5],
                )
                for row in self.bindings
            ]
            return _Result(rowcount=1)
        if "FROM lucy.conversation_capture_states" in normalized:
            return _Result(one=(False,))
        raise AssertionError(f"unexpected SQL: {normalized}")


def _environment() -> dict[str, str]:
    return {
        "RENDER": "true",
        "LUCY_ENVIRONMENT": "production",
        "LUCY_TRANSCRIPT_CAPTURE_ENABLED": "false",
        "LUCY_EXECUTOR_REBIND_AUTHORIZATION": AUTHORIZATION,
        "LUCY_MIGRATION_DATABASE_URL": (
            "postgresql://lucy_migration:secret@dpg-example-a/lucy_6tns"
        ),
        "LUCY_AWS_ACCOUNT_ID": "123456789012",
        "LUCY_RETRIEVAL_EXECUTOR_ALIAS_ARN": (
            "arn:aws:lambda:us-east-1:123456789012:function:retrieval:production"
        ),
        "LUCY_DELETION_EXECUTOR_ALIAS_ARN": (
            "arn:aws:lambda:us-east-1:123456789012:function:deletion:production"
        ),
        "LUCY_RETRIEVAL_RECEIPT_KEY_ARN": (
            "arn:aws:kms:us-east-1:123456789012:key/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        ),
        "LUCY_DELETION_RECEIPT_KEY_ARN": (
            "arn:aws:kms:us-east-1:123456789012:key/bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"
        ),
        "LUCY_EXPECTED_RETRIEVAL_EXECUTOR_VERSION": "2",
        "LUCY_EXPECTED_DELETION_EXECUTOR_VERSION": "2",
        "LUCY_RETRIEVAL_EXECUTOR_VERSION": "3",
        "LUCY_DELETION_EXECUTOR_VERSION": "3",
        "LUCY_SECURITY_STORAGE_EPOCH": "1",
        "LUCY_SECURITY_REGISTRY_EPOCH": "1",
        "LUCY_SECURITY_KEY_EPOCH": "1",
    }


def test_rebind_configuration_accepts_only_private_quarantined_render() -> None:
    config = RebindConfig.from_environment(_environment())

    assert config.migration_url.username == "lucy_migration"
    assert config.retrieval_version == 3
    assert config.expected_retrieval_version == 2


@pytest.mark.parametrize(
    ("name", "value", "diagnostic"),
    [
        ("RENDER", "false", "private-network"),
        ("LUCY_TRANSCRIPT_CAPTURE_ENABLED", "true", "capture"),
        ("LUCY_EXECUTOR_REBIND_AUTHORIZATION", "wrong", "authorization"),
        (
            "LUCY_MIGRATION_DATABASE_URL",
            "postgresql://lucy_migration:secret@example.com/lucy_6tns",
            "private Render",
        ),
        ("LUCY_RETRIEVAL_EXECUTOR_VERSION", "2", "monotonically"),
    ],
)
def test_rebind_configuration_rejects_unsafe_inputs(
    name: str, value: str, diagnostic: str
) -> None:
    environment = _environment()
    environment[name] = value

    with pytest.raises(RebindError, match=diagnostic):
        RebindConfig.from_environment(environment)


def test_rebind_updates_only_versions_and_preserves_historical_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = RebindConfig.from_environment(_environment())
    connection = _Connection(config)
    monkeypatch.setattr(rebind.psycopg, "connect", lambda *_args, **_kwargs: connection)

    report = rebind.run(config)

    assert connection.bindings == rebind._expected_rows(config, target=True)
    assert report["historical_operation_rows_preserved"] is True
    assert report["binding_fields_changed"] == ["executor_version", "configured_at"]
    update_count = sum(
        statement.startswith("UPDATE lucy.executor_bindings_v1")
        for statement in connection.statements
    )
    assert update_count == 2
    assert not any(
        statement.startswith(("DELETE", "INSERT")) for statement in connection.statements
    )


def test_rebind_refuses_unresolved_operations_before_any_update(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = RebindConfig.from_environment(_environment())
    connection = _Connection(config, unresolved=1)
    monkeypatch.setattr(rebind.psycopg, "connect", lambda *_args, **_kwargs: connection)

    with pytest.raises(RebindError, match="unresolved operations"):
        rebind.run(config)

    assert not any(
        statement.startswith("UPDATE lucy.executor_bindings_v1")
        for statement in connection.statements
    )
