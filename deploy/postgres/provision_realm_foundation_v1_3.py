"""Provision one content-free V1.3 realm foundation while admission is closed."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any, Literal, Self
from uuid import UUID

import psycopg
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from deploy.postgres.provision_realm_bindings_v1_3 import (
    _ADMISSION_LOCK,
    _LUCY_DATABASE,
    _MAINTENANCE_LOCK,
    _PRIVATE_RENDER_HOST,
    RealmProvisioningError,
    _conninfo,
    _database_url,
    _insert_exact,
    _required,
)
from lucy.contracts.canonical import canonical_sha256
from lucy.realm_provisioning import RealmSecurityStampV1

AUTHORIZATION = "security-v1.3-quarantined-realm-foundation"
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_SLUG = re.compile(r"[a-z][a-z0-9-]{0,79}\Z")
_FOUNDATION_PREFIX = b"LUCY-REALM-FOUNDATION-SEED-V1\0"


class RealmFoundationSeedV1(BaseModel):
    """Non-secret labels and the last stable ID needed by the private realm."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["1"] = "1"
    object_type: Literal["lucy.realm-foundation-seed.v1"] = (
        "lucy.realm-foundation-seed.v1"
    )
    realm_slug: str = Field(min_length=1, max_length=31)
    account_slug: str = Field(min_length=1, max_length=80)
    account_display_name: str = Field(min_length=1, max_length=200)
    node_slug: str = Field(min_length=1, max_length=80)
    node_display_name: str = Field(min_length=1, max_length=200)
    node_kind: Literal["person", "organization", "project", "community", "service"]
    workspace_slug: str = Field(min_length=1, max_length=80)
    workspace_kind: Literal["private_realm"] = "private_realm"
    service_issuer: str = Field(min_length=1, max_length=300)
    wallet_id: UUID
    provisioned_at: datetime

    @model_validator(mode="after")
    def validate_names(self) -> Self:
        if any(
            _SLUG.fullmatch(value) is None
            for value in (self.realm_slug, self.account_slug, self.node_slug, self.workspace_slug)
        ):
            raise ValueError("realm foundation contains an invalid slug")
        if not self.service_issuer.startswith("lucy://"):
            raise ValueError("realm service issuer must use the lucy scheme")
        if self.provisioned_at.utcoffset() is None:
            raise ValueError("realm foundation timestamp must be timezone-aware")
        return self

    def digest_hex(self) -> str:
        return canonical_sha256(self.model_dump(mode="python"), prefix=_FOUNDATION_PREFIX)


class RealmFoundationConfig(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True, frozen=True)

    migration_url: Any
    stamp: RealmSecurityStampV1
    seed: RealmFoundationSeedV1

    @classmethod
    def from_environment(
        cls, environment: Mapping[str, str] | None = None
    ) -> RealmFoundationConfig:
        values = os.environ if environment is None else environment
        if values.get("RENDER") != "true" or values.get("LUCY_ENVIRONMENT") != "production":
            raise RealmProvisioningError("foundation requires the production Render runtime")
        if values.get("LUCY_TRANSCRIPT_CAPTURE_ENABLED") != "false":
            raise RealmProvisioningError("transcript capture must remain disabled")
        if values.get("LUCY_REALM_FOUNDATION_AUTHORIZATION") != AUTHORIZATION:
            raise RealmProvisioningError("the exact reviewed foundation authorization is required")
        migration_url = _database_url(_required(values, "LUCY_MIGRATION_DATABASE_URL"))
        if (
            migration_url.username != "lucy_migration"
            or migration_url.host is None
            or _PRIVATE_RENDER_HOST.fullmatch(migration_url.host) is None
            or migration_url.database is None
            or _LUCY_DATABASE.fullmatch(migration_url.database) is None
            or migration_url.port not in (None, 5432)
        ):
            raise RealmProvisioningError("foundation requires the private Lucy migration login")
        try:
            stamp = RealmSecurityStampV1.model_validate_json(
                _required(values, "LUCY_REALM_SECURITY_STAMP_JSON")
            )
            seed = RealmFoundationSeedV1.model_validate_json(
                _required(values, "LUCY_REALM_FOUNDATION_SEED_JSON")
            )
        except (ValidationError, ValueError) as exc:
            raise RealmProvisioningError("realm foundation input is invalid") from exc
        for name, actual in (
            ("LUCY_REALM_SECURITY_STAMP_SHA256", stamp.digest_hex()),
            ("LUCY_REALM_FOUNDATION_SEED_SHA256", seed.digest_hex()),
        ):
            reviewed = _required(values, name)
            if _DIGEST.fullmatch(reviewed) is None or reviewed != actual:
                raise RealmProvisioningError("realm foundation digest does not match")
        if seed.realm_slug != stamp.realm_slug:
            raise RealmProvisioningError("realm foundation does not match the security stamp")
        return cls(migration_url=migration_url, stamp=stamp, seed=seed)


def apply_foundation(
    connection: psycopg.Connection[Any],
    stamp: RealmSecurityStampV1,
    seed: RealmFoundationSeedV1,
) -> bool:
    now = seed.provisioned_at
    inserted = [
        _insert_exact(
            connection,
            "tenant_accounts",
            "id",
            {
                "id": stamp.tenant_account_id,
                "slug": seed.account_slug,
                "display_name": seed.account_display_name,
                "created_at": now,
            },
        ),
        _insert_exact(
            connection,
            "nodes",
            "id",
            {
                "id": stamp.node_id,
                "slug": seed.node_slug,
                "display_name": seed.node_display_name,
                "node_kind": seed.node_kind,
                "created_at": now,
            },
        ),
        _insert_exact(
            connection,
            "node_tenures",
            "id",
            {
                "id": stamp.node_tenure_id,
                "node_id": stamp.node_id,
                "account_id": stamp.tenant_account_id,
                "sequence": stamp.tenure_epoch,
                "starts_at": now,
                "ends_at": None,
            },
        ),
        _insert_exact(
            connection,
            "security_realms",
            "id",
            {"id": stamp.security_realm_id, "slug": stamp.realm_slug, "created_at": now},
        ),
        _insert_exact(
            connection,
            "realm_bindings",
            "id",
            {
                "id": stamp.realm_binding_id,
                "tenure_id": stamp.node_tenure_id,
                "realm_id": stamp.security_realm_id,
                "binding_version": stamp.binding_generation,
                "valid_from": now,
                "valid_to": None,
            },
        ),
        _insert_exact(
            connection,
            "workspaces",
            "id",
            {
                "id": stamp.workspace_id,
                "node_id": stamp.node_id,
                "tenure_id": stamp.node_tenure_id,
                "slug": seed.workspace_slug,
                "workspace_kind": seed.workspace_kind,
                "created_at": now,
            },
        ),
        _insert_exact(
            connection,
            "wallet_registrations",
            "id",
            {
                "id": seed.wallet_id,
                "node_id": stamp.node_id,
                "tenure_id": stamp.node_tenure_id,
                "status": "REGISTERED_NONSPENDABLE",
                "created_at": now,
            },
        ),
    ]
    principals = (
        (
            stamp.routine_principal_id,
            stamp.routine_login,
            f"{seed.node_display_name} routine service",
        ),
        (
            stamp.policy_principal_id,
            stamp.policy_login,
            f"{seed.node_display_name} policy service",
        ),
        (
            stamp.workflow_principal_id,
            stamp.workflow_login,
            f"{seed.node_display_name} workflow service",
        ),
        (
            stamp.finality_principal_id,
            stamp.finality_login,
            f"{seed.node_display_name} finality service",
        ),
    )
    for principal_id, subject, display_name in principals:
        inserted.append(
            _insert_exact(
                connection,
                "principals",
                "id",
                {
                    "id": principal_id,
                    "issuer": seed.service_issuer,
                    "subject": subject,
                    "principal_kind": "service",
                    "display_name": display_name,
                    "created_at": now,
                },
            )
        )
    if any(inserted) and not all(inserted):
        raise RealmProvisioningError("realm foundation exists only partially")
    return all(inserted)


def run(config: RealmFoundationConfig) -> dict[str, object]:
    with psycopg.connect(_conninfo(config.migration_url)) as connection:
        connection.execute("SET LOCAL lock_timeout = '10s'")
        connection.execute("SET LOCAL statement_timeout = '120s'")
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (_MAINTENANCE_LOCK,))
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (_ADMISSION_LOCK,))
        boundary = connection.execute(
            "SELECT (SELECT state FROM lucy.runtime_admission WHERE singleton),"
            "lucy.capture_boundary_safe_v1(),"
            "(SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid())"
        ).fetchone()
        if boundary != ("quarantined", True, True):
            raise RealmProvisioningError("database is outside the reviewed foundation boundary")
        inserted = apply_foundation(connection, config.stamp, config.seed)
    return {
        "contract": "lucy.realm-foundation-application.v1",
        "status": "passed",
        "realm_slug": config.stamp.realm_slug,
        "security_realm_id": str(config.stamp.security_realm_id),
        "foundation_digest": config.seed.digest_hex(),
        "replayed": not inserted,
    }


def main(argv: Sequence[str] | None = None) -> int:
    if argv:
        raise RealmProvisioningError("this deployment utility accepts no command-line values")
    try:
        report = run(RealmFoundationConfig.from_environment())
    except RealmProvisioningError as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, sort_keys=True))
        return 1
    except Exception as exc:
        print(json.dumps({"status": "failed", "error_type": type(exc).__name__}, sort_keys=True))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
