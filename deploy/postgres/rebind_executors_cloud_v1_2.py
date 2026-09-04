"""Rebind quarantined PostgreSQL workflows to reviewed Lambda versions.

Run only from a temporary Render migration utility after a policy trust-store
rotation. The utility accepts no runtime database passwords, transcript data,
or private signing material. It verifies the exact prior binding, applies the
reviewed SQL while admission remains quarantined, and emits content-free facts.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import psycopg
from sqlalchemy.engine import URL, make_url

try:
    from . import render_security_v1_2_sql as renderer
except ImportError:  # Direct script execution places deploy/postgres on sys.path.
    import render_security_v1_2_sql as renderer

AUTHORIZATION = "security-v1.2-executor-rebind"
_PRIVATE_RENDER_HOST = re.compile(r"dpg-[a-z0-9-]+-a\Z")
_LUCY_DATABASE = re.compile(r"lucy(?:_[a-z0-9]+)?\Z")


class RebindError(RuntimeError):
    """A content-free rebind precondition or verification failure."""


@dataclass(frozen=True)
class RebindConfig:
    migration_url: URL
    aws_account_id: str
    retrieval_alias_arn: str
    deletion_alias_arn: str
    retrieval_receipt_key_arn: str
    deletion_receipt_key_arn: str
    expected_retrieval_version: int
    expected_deletion_version: int
    retrieval_version: int
    deletion_version: int
    storage_epoch: int
    registry_epoch: int
    key_epoch: int

    @classmethod
    def from_environment(cls, environment: Mapping[str, str] | None = None) -> RebindConfig:
        values = os.environ if environment is None else environment
        if values.get("RENDER") != "true":
            raise RebindError("rebind requires the Render private-network runtime")
        if values.get("LUCY_ENVIRONMENT") != "production":
            raise RebindError("rebind requires the production environment")
        if values.get("LUCY_TRANSCRIPT_CAPTURE_ENABLED") != "false":
            raise RebindError("transcript capture must remain disabled")
        if values.get("LUCY_EXECUTOR_REBIND_AUTHORIZATION") != AUTHORIZATION:
            raise RebindError("the exact reviewed rebind authorization is required")

        migration = _database_url(_required(values, "LUCY_MIGRATION_DATABASE_URL"))
        if migration.username != "lucy_migration":
            raise RebindError("the migration URL must use lucy_migration")
        if migration.host is None or _PRIVATE_RENDER_HOST.fullmatch(migration.host) is None:
            raise RebindError("the migration URL must use the private Render database host")
        if (
            migration.database is None
            or _LUCY_DATABASE.fullmatch(migration.database) is None
            or migration.port not in (None, 5432)
        ):
            raise RebindError("the migration URL must target the reviewed Lucy database")

        config = cls(
            migration_url=migration,
            aws_account_id=_required(values, "LUCY_AWS_ACCOUNT_ID"),
            retrieval_alias_arn=_required(values, "LUCY_RETRIEVAL_EXECUTOR_ALIAS_ARN"),
            deletion_alias_arn=_required(values, "LUCY_DELETION_EXECUTOR_ALIAS_ARN"),
            retrieval_receipt_key_arn=_required(values, "LUCY_RETRIEVAL_RECEIPT_KEY_ARN"),
            deletion_receipt_key_arn=_required(values, "LUCY_DELETION_RECEIPT_KEY_ARN"),
            expected_retrieval_version=_positive_int(
                values, "LUCY_EXPECTED_RETRIEVAL_EXECUTOR_VERSION"
            ),
            expected_deletion_version=_positive_int(
                values, "LUCY_EXPECTED_DELETION_EXECUTOR_VERSION"
            ),
            retrieval_version=_positive_int(values, "LUCY_RETRIEVAL_EXECUTOR_VERSION"),
            deletion_version=_positive_int(values, "LUCY_DELETION_EXECUTOR_VERSION"),
            storage_epoch=_positive_int(values, "LUCY_SECURITY_STORAGE_EPOCH"),
            registry_epoch=_positive_int(values, "LUCY_SECURITY_REGISTRY_EPOCH"),
            key_epoch=_positive_int(values, "LUCY_SECURITY_KEY_EPOCH"),
        )
        if (
            config.retrieval_version <= config.expected_retrieval_version
            or config.deletion_version <= config.expected_deletion_version
        ):
            raise RebindError("target executor versions must advance monotonically")
        return config


def _required(values: Mapping[str, str], name: str) -> str:
    value = values.get(name, "").strip()
    if not value:
        raise RebindError(f"missing required configuration: {name}")
    return value


def _positive_int(values: Mapping[str, str], name: str) -> int:
    try:
        value = int(_required(values, name))
    except ValueError as exc:
        raise RebindError(f"{name} must be a positive integer") from exc
    if value < 1:
        raise RebindError(f"{name} must be a positive integer")
    return value


def _database_url(raw: str) -> URL:
    try:
        parsed = make_url(raw)
    except Exception as exc:
        raise RebindError("invalid PostgreSQL URL") from exc
    if parsed.drivername not in {"postgresql", "postgresql+psycopg"}:
        raise RebindError("only PostgreSQL psycopg URLs are accepted")
    if not parsed.username or not parsed.password or not parsed.host or not parsed.database:
        raise RebindError("database URL requires user, password, host, and database")
    return parsed.set(drivername="postgresql+psycopg").update_query_dict({"sslmode": "require"})


def _conninfo(url: URL) -> str:
    return url.set(drivername="postgresql").render_as_string(hide_password=False)


def _strip_reviewed_psql_header(script: str) -> str:
    lines = script.splitlines()
    meta = [line.strip() for line in lines if line.lstrip().startswith("\\")]
    if meta not in ([], [r"\set ON_ERROR_STOP on"]):
        raise RebindError("unexpected psql meta-command in reviewed SQL")
    return "\n".join(line for line in lines if not line.lstrip().startswith("\\")) + "\n"


def _binding_rows(connection: psycopg.Connection[Any]) -> list[tuple[Any, ...]]:
    return list(
        connection.execute(
            "SELECT action,executor_alias_arn,executor_version,receipt_key_id,active "
            "FROM lucy.executor_bindings_v1 WHERE environment='production' ORDER BY action"
        ).fetchall()
    )


def _expected_rows(config: RebindConfig, *, target: bool) -> list[tuple[Any, ...]]:
    retrieval_version = (
        config.retrieval_version if target else config.expected_retrieval_version
    )
    deletion_version = config.deletion_version if target else config.expected_deletion_version
    return sorted(
        [
            (
                "evidence.retrieve",
                config.retrieval_alias_arn,
                retrieval_version,
                config.retrieval_receipt_key_arn,
                True,
            ),
            (
                "evidence.delete",
                config.deletion_alias_arn,
                deletion_version,
                config.deletion_receipt_key_arn,
                True,
            ),
        ]
    )


def run(config: RebindConfig) -> dict[str, Any]:
    rendered = renderer.render_bindings(
        aws_account_id=config.aws_account_id,
        retrieval_alias_arn=config.retrieval_alias_arn,
        deletion_alias_arn=config.deletion_alias_arn,
        retrieval_receipt_key_arn=config.retrieval_receipt_key_arn,
        deletion_receipt_key_arn=config.deletion_receipt_key_arn,
        retrieval_version=config.retrieval_version,
        deletion_version=config.deletion_version,
        security_storage_epoch=config.storage_epoch,
        security_registry_epoch=config.registry_epoch,
        security_key_epoch=config.key_epoch,
    )
    with psycopg.connect(_conninfo(config.migration_url), autocommit=True) as connection:
        tls = connection.execute(
            "SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()"
        ).fetchone()
        if tls is None or tls[0] is not True:
            raise RebindError("database connection is not TLS protected")
        admission = connection.execute(
            "SELECT state FROM lucy.runtime_admission WHERE singleton"
        ).fetchone()
        if admission != ("quarantined",):
            raise RebindError("runtime admission must remain quarantined")
        if _binding_rows(connection) != _expected_rows(config, target=False):
            raise RebindError("existing executor bindings differ from the reviewed prior state")
        connection.execute(_strip_reviewed_psql_header(rendered), prepare=False)
        if _binding_rows(connection) != _expected_rows(config, target=True):
            raise RebindError("executor bindings did not reach the reviewed target state")
        capture = connection.execute(
            "SELECT EXISTS (SELECT 1 FROM lucy.conversation_capture_states WHERE capture_enabled) "
            "OR EXISTS (SELECT 1 FROM lucy.capture_receipts WHERE capture_enabled)"
        ).fetchone()
        final_admission = connection.execute(
            "SELECT state FROM lucy.runtime_admission WHERE singleton"
        ).fetchone()
        if capture != (False,) or final_admission != ("quarantined",):
            raise RebindError("rebind changed capture or admission safety state")
    return {
        "contract": "lucy.security-executor-rebind.v1.2",
        "status": "passed",
        "from_versions": {
            "retrieval": config.expected_retrieval_version,
            "deletion": config.expected_deletion_version,
        },
        "to_versions": {
            "retrieval": config.retrieval_version,
            "deletion": config.deletion_version,
        },
        "bindings_sql_sha256": hashlib.sha256(rendered.encode()).hexdigest(),
        "runtime_admission": "quarantined",
        "capture_enabled": False,
    }


def main(argv: Sequence[str] | None = None) -> int:
    if argv:
        raise RebindError("this deployment utility accepts no command-line values")
    try:
        report = run(RebindConfig.from_environment())
    except RebindError as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, sort_keys=True))
        return 1
    except Exception as exc:
        print(json.dumps({"status": "failed", "error_type": type(exc).__name__}, sort_keys=True))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
