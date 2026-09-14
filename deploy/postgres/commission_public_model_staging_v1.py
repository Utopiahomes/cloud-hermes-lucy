"""Commission the isolated Public Lucy staging-test cost boundary.

Run only as a temporary Render job with no provider credential. The job creates
one realm-qualified execute-only PostgreSQL LOGIN and one immutable cost policy.
It never enables website model traffic and never calls the model provider.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import psycopg
from psycopg import sql
from pydantic import ValidationError
from sqlalchemy.engine import URL

from deploy.postgres.bootstrap_realm_cloud_v1_3 import (
    _LUCY_DATABASE,
    _PRIVATE_RENDER_HOST,
    BootstrapError,
    _conninfo,
    _database_url,
)
from lucy.cost_admission import ProviderCostPolicyV1
from lucy.public_model_activation import UtopiaPublicModelActivationManifestV2
from lucy.readiness import ADMISSION_LOCK

AUTHORIZATION = "utopia-public-model-staging-test-v1"
MAINTENANCE_LOCK = 0x4C5543594D53
LOGIN = "lucy_utopia_cost_admission"
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")

_COST_FUNCTIONS = (
    "lucy.reserve_provider_attempt_v1(uuid,text,uuid,uuid,text,text,text,text,text,"
    "text,bigint,integer,integer,integer,integer,timestamptz)",
    "lucy.claim_provider_submission_v1(uuid)",
    "lucy.mark_provider_attempt_unknown_v1(uuid)",
    "lucy.settle_provider_attempt_v1(uuid,bigint,text)",
)
_PROTECTED_TABLES = (
    "lucy.provider_cost_policies_v1",
    "lucy.provider_attempts_v1",
    "lucy.exposure_reservations_v1",
    "lucy.cost_events_v1",
    "lucy.cost_recovery_outbox_v1",
)


class PublicModelCommissioningError(RuntimeError):
    """A content-free staging commissioning failure."""


@dataclass(frozen=True)
class PublicModelCommissioningConfig:
    migration_url: URL
    model_url: URL
    manifest: UtopiaPublicModelActivationManifestV2

    @classmethod
    def from_environment(
        cls, environment: Mapping[str, str] | None = None
    ) -> PublicModelCommissioningConfig:
        values = os.environ if environment is None else environment
        if values.get("RENDER") != "true" or values.get("LUCY_ENVIRONMENT") != "production":
            raise PublicModelCommissioningError("commissioning requires production Render")
        if values.get("LUCY_TRANSCRIPT_CAPTURE_ENABLED") != "false":
            raise PublicModelCommissioningError("transcript capture must remain disabled")
        if values.get("LUCY_PUBLIC_MODEL_COMMISSIONING_AUTHORIZATION") != AUTHORIZATION:
            raise PublicModelCommissioningError("exact staging authorization is required")
        try:
            migration_url = _database_url(_required(values, "LUCY_MIGRATION_DATABASE_URL"))
            model_url = _database_url(_required(values, "LUCY_PUBLIC_MODEL_DATABASE_URL"))
        except BootstrapError as exc:
            raise PublicModelCommissioningError("commissioning database URL is invalid") from exc
        if migration_url.username != "lucy_migration":
            raise PublicModelCommissioningError("migration identity differs")
        if model_url.username != LOGIN or not model_url.password:
            raise PublicModelCommissioningError("model cost identity differs")
        expected_target = (
            migration_url.host,
            migration_url.port or 5432,
            migration_url.database,
        )
        if (
            migration_url.host is None
            or _PRIVATE_RENDER_HOST.fullmatch(migration_url.host) is None
            or migration_url.database is None
            or _LUCY_DATABASE.fullmatch(migration_url.database) is None
            or migration_url.port not in (None, 5432)
            or (model_url.host, model_url.port or 5432, model_url.database)
            != expected_target
        ):
            raise PublicModelCommissioningError("commissioning database boundary differs")
        try:
            manifest = UtopiaPublicModelActivationManifestV2.model_validate_json(
                _required(values, "LUCY_PUBLIC_MODEL_ACTIVATION_MANIFEST_JSON")
            )
        except (ValidationError, ValueError) as exc:
            raise PublicModelCommissioningError("activation manifest is invalid") from exc
        reviewed_digest = _required(values, "LUCY_PUBLIC_MODEL_ACTIVATION_MANIFEST_SHA256")
        if (
            _DIGEST.fullmatch(reviewed_digest) is None
            or reviewed_digest != manifest.digest_hex()
            or manifest.release_state != "staging-test"
            or manifest.model_traffic_enabled
            or manifest.transcript_capture_enabled
            or manifest.cost_policy.kill_state != "enabled"
            or manifest.authority.database_login != LOGIN
        ):
            raise PublicModelCommissioningError("activation manifest is not staging-test exact")
        return cls(migration_url=migration_url, model_url=model_url, manifest=manifest)


def _required(values: Mapping[str, str], name: str) -> str:
    value = values.get(name, "").strip()
    if not value:
        raise PublicModelCommissioningError(f"required commissioning value is missing: {name}")
    return value


def _policy(manifest: UtopiaPublicModelActivationManifestV2) -> ProviderCostPolicyV1:
    cost = manifest.cost_policy
    execution = manifest.execution
    return ProviderCostPolicyV1(
        policy_id=cost.policy_id,
        version=cost.version,
        node_id=manifest.authority.node_id,
        channel_binding_id=manifest.authority.channel_binding_id,
        provider=manifest.routing.provider,
        model=manifest.routing.model,
        rate_version=manifest.routing.rate_version,
        effective_at=cost.effective_at,
        kill_state=cost.kill_state,
        platform_daily_cap_microusd=cost.platform_daily_cap_microusd,
        node_daily_cap_microusd=cost.node_daily_cap_microusd,
        site_daily_cap_microusd=cost.site_daily_cap_microusd,
        provider_daily_cap_microusd=cost.provider_daily_cap_microusd,
        outstanding_cap_microusd=cost.outstanding_cap_microusd,
        concurrency_limit=cost.concurrency_limit,
        requests_per_minute=cost.requests_per_minute,
        session_requests_per_minute=cost.session_requests_per_minute,
        ip_requests_per_minute=cost.ip_requests_per_minute,
        per_request_cap_microusd=cost.per_attempt_cap_microusd,
        max_input_tokens=execution.max_input_tokens,
        max_output_tokens=max(
            execution.generator_max_output_tokens,
            execution.verifier_max_output_tokens,
        ),
        max_request_bytes=manifest.ingress.max_model_request_bytes,
        timeout_seconds=execution.provider_timeout_seconds,
    )


def _role_is_exact(connection: psycopg.Connection[Any]) -> bool:
    row = connection.execute(
        "SELECT rolcanlogin,rolsuper,rolinherit,rolcreaterole,rolcreatedb,"
        "rolreplication,rolbypassrls FROM pg_roles WHERE rolname=%s",
        (LOGIN,),
    ).fetchone()
    return row == (True, False, False, False, False, False, False)


def _configure_login(connection: psycopg.Connection[Any], password: str) -> bool:
    exists = connection.execute(
        "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=%s)", (LOGIN,)
    ).fetchone() == (True,)
    if exists and not _role_is_exact(connection):
        raise PublicModelCommissioningError("existing model cost identity is elevated")
    members = connection.execute(
        "SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.member "
        "WHERE r.rolname=%s LIMIT 1",
        (LOGIN,),
    ).fetchone()
    if members is not None:
        raise PublicModelCommissioningError("model cost identity has inherited membership")
    role = sql.Identifier(LOGIN)
    if exists:
        connection.execute(
            sql.SQL("ALTER ROLE {} PASSWORD {}").format(role, sql.Literal(password))
        )
    else:
        connection.execute(
            sql.SQL(
                "CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB NOCREATEROLE "
                "NOINHERIT NOREPLICATION NOBYPASSRLS"
            ).format(role, sql.Literal(password))
        )
    connection.execute(
        sql.SQL("REVOKE CONNECT,TEMP ON DATABASE {} FROM {}").format(
            sql.Identifier(str(connection.info.dbname)), role
        )
    )
    connection.execute(
        sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
            sql.Identifier(str(connection.info.dbname)), role
        )
    )
    connection.execute(sql.SQL("REVOKE ALL ON SCHEMA lucy,public FROM {}").format(role))
    for object_type in ("TABLES", "SEQUENCES", "FUNCTIONS"):
        connection.execute(
            sql.SQL("REVOKE ALL PRIVILEGES ON ALL {} IN SCHEMA lucy FROM {}").format(
                sql.SQL(object_type), role
            )
        )
    connection.execute(sql.SQL("GRANT USAGE ON SCHEMA lucy TO {}").format(role))
    connection.execute(
        sql.SQL("GRANT SELECT ON lucy.lifecycle,lucy.runtime_admission TO {}").format(role)
    )
    for function in _COST_FUNCTIONS:
        connection.execute(
            sql.SQL("GRANT EXECUTE ON FUNCTION {} TO {}").format(
                sql.SQL(function), role
            )
        )
    return not exists


def _insert_policy(
    connection: psycopg.Connection[Any], policy: ProviderCostPolicyV1
) -> bool:
    values = policy.model_dump(mode="python") | {
        "policy_digest": policy.digest_hex(),
        "created_at": policy.effective_at,
    }
    values["id"] = values.pop("policy_id")
    columns = tuple(values)
    existing = connection.execute(
        sql.SQL("SELECT {} FROM lucy.provider_cost_policies_v1 WHERE id=%s").format(
            sql.SQL(",").join(map(sql.Identifier, columns))
        ),
        (policy.policy_id,),
    ).fetchone()
    if existing is not None:
        if existing != tuple(values[name] for name in columns):
            raise PublicModelCommissioningError("existing model cost policy differs")
        return False
    conflict = connection.execute(
        "SELECT 1 FROM lucy.provider_cost_policies_v1 WHERE channel_binding_id=%s "
        "AND provider=%s AND model=%s AND version=%s",
        (policy.channel_binding_id, policy.provider, policy.model, policy.version),
    ).fetchone()
    if conflict is not None:
        raise PublicModelCommissioningError("model cost policy version conflicts")
    connection.execute(
        sql.SQL("INSERT INTO lucy.provider_cost_policies_v1({}) VALUES({})").format(
            sql.SQL(",").join(map(sql.Identifier, columns)),
            sql.SQL(",").join(sql.Placeholder(name) for name in columns),
        ),
        values,
    )
    return True


def _verify_runtime_identity(config: PublicModelCommissioningConfig) -> None:
    with psycopg.connect(_conninfo(config.model_url)) as connection:
        connection.execute("SET TRANSACTION READ ONLY")
        boundary = connection.execute(
            "SELECT session_user,(SELECT state FROM lucy.runtime_admission WHERE singleton),"
            "(SELECT state FROM lucy.lifecycle WHERE singleton),"
            "(SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid())"
        ).fetchone()
        if boundary != (
            LOGIN,
            "ready",
            "ready",
            True,
        ):
            raise PublicModelCommissioningError("model cost runtime boundary differs")
        if not _role_is_exact(connection):
            raise PublicModelCommissioningError("model cost runtime identity differs")
        for function in _COST_FUNCTIONS:
            allowed = connection.execute(
                "SELECT has_function_privilege(session_user,%s,'EXECUTE')", (function,)
            ).fetchone()
            if allowed != (True,):
                raise PublicModelCommissioningError("model cost function grant differs")
        for table in _PROTECTED_TABLES:
            direct = connection.execute(
                "SELECT has_table_privilege(session_user,%s,'SELECT') OR "
                "has_table_privilege(session_user,%s,'INSERT') OR "
                "has_table_privilege(session_user,%s,'UPDATE') OR "
                "has_table_privilege(session_user,%s,'DELETE') OR "
                "has_table_privilege(session_user,%s,'TRUNCATE')",
                (table, table, table, table, table),
            ).fetchone()
            if direct != (False,):
                raise PublicModelCommissioningError("model cost table authority exceeds scope")


def commission(config: PublicModelCommissioningConfig) -> dict[str, object]:
    manifest = config.manifest
    policy = _policy(manifest)
    with psycopg.connect(_conninfo(config.migration_url)) as connection:
        connection.execute("SET LOCAL lock_timeout='15s'")
        connection.execute("SET LOCAL statement_timeout='120s'")
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (MAINTENANCE_LOCK,))
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (ADMISSION_LOCK,))
        boundary = connection.execute(
            "SELECT current_user,(SELECT version_num FROM public.alembic_version),"
            "(SELECT state FROM lucy.runtime_admission WHERE singleton),"
            "(SELECT state FROM lucy.lifecycle WHERE singleton),"
            "(SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid())"
        ).fetchone()
        if boundary != (
            "lucy_migration",
            manifest.artifacts.schema_revision,
            "ready",
            "ready",
            True,
        ):
            raise PublicModelCommissioningError("pre-commissioning boundary differs")
        generic = connection.execute(
            "SELECT rolcanlogin,rolsuper,rolinherit,rolcreaterole,rolcreatedb,"
            "rolreplication,rolbypassrls FROM pg_roles WHERE rolname='lucy_cost_admission'"
        ).fetchone()
        if generic != (False, False, False, False, False, False, False):
            raise PublicModelCommissioningError("generic cost capability is not inert")
        channel = connection.execute(
            "SELECT node_id,active,channel_kind,hostname FROM lucy.channel_bindings WHERE id=%s",
            (manifest.authority.channel_binding_id,),
        ).fetchone()
        if channel != (
            manifest.authority.node_id,
            True,
            "website_public",
            "www.utopiahomes.com",
        ):
            raise PublicModelCommissioningError("public model channel binding differs")
        password = config.model_url.password
        assert password is not None
        login_created = _configure_login(connection, password)
        policy_created = _insert_policy(connection, policy)
    _verify_runtime_identity(config)
    return {
        "contract": "lucy.utopia.public-model-staging-commissioning.v1",
        "status": "passed",
        "release_decision_id": manifest.release_decision_id,
        "manifest_digest": manifest.digest_hex(),
        "schema_revision": manifest.artifacts.schema_revision,
        "database_login": LOGIN,
        "policy_id": str(policy.policy_id),
        "policy_digest": policy.digest_hex(),
        "login_created": login_created,
        "policy_created": policy_created,
        "runtime_admission": "ready",
        "transcript_capture_enabled": False,
        "model_traffic_enabled": False,
        "provider_called": False,
    }


def main() -> int:
    try:
        report = commission(PublicModelCommissioningConfig.from_environment())
    except PublicModelCommissioningError as exc:
        print(
            json.dumps(
                {
                    "contract": "lucy.utopia.public-model-staging-commissioning.v1",
                    "status": "failed",
                    "error": str(exc),
                },
                sort_keys=True,
            )
        )
        return 1
    except Exception as exc:
        print(
            json.dumps(
                {
                    "contract": "lucy.utopia.public-model-staging-commissioning.v1",
                    "status": "failed",
                    "error_type": type(exc).__name__,
                },
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
