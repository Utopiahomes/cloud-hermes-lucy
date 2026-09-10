"""Provision or revoke one exact synthetic owner for V1.3 cloud acceptance.

This command is migration-only, quarantine-only, and content-free. It cannot
create a customer identity or a public channel, and it never opens admission.
"""

from __future__ import annotations

import argparse
import json
import os
import re
from collections.abc import Mapping
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
from lucy.readiness import R1_SCHEMA_REVISION
from lucy.realm_provisioning import RealmSecurityStampV1

Action = Literal["setup", "revoke"]
AUTHORIZATION = "security-v1.3-synthetic-owner-quarantined"
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_HOSTNAME = re.compile(r"synthetic-[a-z0-9-]{1,220}\.invalid\Z")
_PREFIX = b"LUCY-SYNTHETIC-OWNER-MANIFEST-V1\0"


class SyntheticOwnerManifestV1(BaseModel):
    """Reviewed, non-secret identity material for one acceptance principal."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["1"] = "1"
    object_type: Literal["lucy.synthetic-owner-manifest.v1"] = (
        "lucy.synthetic-owner-manifest.v1"
    )
    realm_slug: str = Field(pattern=r"^[a-z][a-z0-9-]{0,30}$")
    principal_id: UUID
    membership_id: UUID
    channel_binding_id: UUID
    identity_issuer: str = Field(pattern=r"^lucy://synthetic-commissioning/[a-z0-9-]+$")
    identity_subject: str = Field(pattern=r"^synthetic-owner-[a-z0-9-]+$")
    hostname: str = Field(min_length=1, max_length=253)
    provisioned_at: datetime

    @model_validator(mode="after")
    def validate_synthetic_boundary(self) -> Self:
        if _HOSTNAME.fullmatch(self.hostname) is None:
            raise ValueError("synthetic owner hostname is invalid")
        if self.provisioned_at.utcoffset() is None:
            raise ValueError("synthetic owner timestamp must be timezone-aware")
        return self

    def digest_hex(self) -> str:
        return canonical_sha256(self.model_dump(mode="python"), prefix=_PREFIX)


class SyntheticOwnerConfig(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True, frozen=True)

    migration_url: Any
    stamp: RealmSecurityStampV1
    manifest: SyntheticOwnerManifestV1

    @classmethod
    def from_environment(
        cls, environment: Mapping[str, str] | None = None
    ) -> SyntheticOwnerConfig:
        values = os.environ if environment is None else environment
        if values.get("RENDER") != "true" or values.get("LUCY_ENVIRONMENT") != "production":
            raise RealmProvisioningError("synthetic authority requires production Render")
        if values.get("LUCY_TRANSCRIPT_CAPTURE_ENABLED") != "false":
            raise RealmProvisioningError("transcript capture must remain disabled")
        if values.get("LUCY_SYNTHETIC_OWNER_AUTHORIZATION") != AUTHORIZATION:
            raise RealmProvisioningError("exact synthetic owner authorization is required")
        migration_url = _database_url(_required(values, "LUCY_MIGRATION_DATABASE_URL"))
        if (
            migration_url.username != "lucy_migration"
            or migration_url.host is None
            or _PRIVATE_RENDER_HOST.fullmatch(migration_url.host) is None
            or migration_url.database is None
            or _LUCY_DATABASE.fullmatch(migration_url.database) is None
            or migration_url.port not in (None, 5432)
        ):
            raise RealmProvisioningError("synthetic authority requires private migration login")
        try:
            stamp = RealmSecurityStampV1.model_validate_json(
                _required(values, "LUCY_REALM_SECURITY_STAMP_JSON")
            )
            manifest = SyntheticOwnerManifestV1.model_validate_json(
                _required(values, "LUCY_SYNTHETIC_OWNER_MANIFEST_JSON")
            )
        except (ValidationError, ValueError) as exc:
            raise RealmProvisioningError("synthetic owner input is invalid") from exc
        for name, actual in (
            ("LUCY_REALM_SECURITY_STAMP_SHA256", stamp.digest_hex()),
            ("LUCY_SYNTHETIC_OWNER_MANIFEST_SHA256", manifest.digest_hex()),
        ):
            reviewed = _required(values, name)
            if _DIGEST.fullmatch(reviewed) is None or reviewed != actual:
                raise RealmProvisioningError("synthetic owner digest does not match")
        if manifest.realm_slug != stamp.realm_slug:
            raise RealmProvisioningError("synthetic owner realm differs")
        return cls(migration_url=migration_url, stamp=stamp, manifest=manifest)


def _exact_state(
    connection: psycopg.Connection[Any],
    stamp: RealmSecurityStampV1,
    manifest: SyntheticOwnerManifestV1,
) -> tuple[str | None, tuple[str, int] | None, tuple[bool, int] | None]:
    principal = connection.execute(
        "SELECT status FROM lucy.principals WHERE id=%s AND issuer=%s AND subject=%s "
        "AND principal_kind='human'",
        (manifest.principal_id, manifest.identity_issuer, manifest.identity_subject),
    ).fetchone()
    membership = connection.execute(
        "SELECT status,generation FROM lucy.node_memberships WHERE id=%s "
        "AND principal_id=%s AND workspace_id=%s AND role='owner'",
        (manifest.membership_id, manifest.principal_id, stamp.workspace_id),
    ).fetchone()
    channel = connection.execute(
        "SELECT active,generation FROM lucy.channel_bindings WHERE id=%s AND hostname=%s "
        "AND node_id=%s AND tenure_id=%s AND workspace_id=%s AND channel_kind='internal'",
        (
            manifest.channel_binding_id,
            manifest.hostname,
            stamp.node_id,
            stamp.node_tenure_id,
            stamp.workspace_id,
        ),
    ).fetchone()
    return (
        None if principal is None else str(principal[0]),
        None if membership is None else (str(membership[0]), int(membership[1])),
        None if channel is None else (bool(channel[0]), int(channel[1])),
    )


def run(config: SyntheticOwnerConfig, action: Action) -> dict[str, object]:
    stamp, manifest = config.stamp, config.manifest
    with psycopg.connect(_conninfo(config.migration_url)) as connection:
        connection.execute("SET LOCAL lock_timeout = '15s'")
        connection.execute("SET LOCAL statement_timeout = '120s'")
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (_MAINTENANCE_LOCK,))
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (_ADMISSION_LOCK,))
        if connection.execute("SELECT current_user").fetchone() != ("lucy_migration",):
            raise RealmProvisioningError("synthetic owner session is not migration owner")
        if connection.execute(
            "SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()"
        ).fetchone() != (True,):
            raise RealmProvisioningError("synthetic owner connection is not TLS protected")
        if connection.execute(
            "SELECT version_num FROM public.alembic_version"
        ).fetchone() != (R1_SCHEMA_REVISION,):
            raise RealmProvisioningError("database is not at reviewed V1.3 revision")
        if connection.execute(
            "SELECT state FROM lucy.runtime_admission WHERE singleton"
        ).fetchone() != ("quarantined",):
            raise RealmProvisioningError("synthetic owner changes require quarantine")

        before = _exact_state(connection, stamp, manifest)
        if action == "setup":
            inserted = (
                _insert_exact(
                    connection,
                    "principals",
                    "id",
                    {
                        "id": manifest.principal_id,
                        "issuer": manifest.identity_issuer,
                        "subject": manifest.identity_subject,
                        "principal_kind": "human",
                        "display_name": "Synthetic commissioning owner",
                        "created_at": manifest.provisioned_at,
                        "status": "active",
                    },
                ),
                _insert_exact(
                    connection,
                    "node_memberships",
                    "id",
                    {
                        "id": manifest.membership_id,
                        "principal_id": manifest.principal_id,
                        "workspace_id": stamp.workspace_id,
                        "role": "owner",
                        "status": "active",
                        "granted_at": manifest.provisioned_at,
                        "generation": 1,
                    },
                ),
                _insert_exact(
                    connection,
                    "channel_bindings",
                    "id",
                    {
                        "id": manifest.channel_binding_id,
                        "hostname": manifest.hostname,
                        "node_id": stamp.node_id,
                        "tenure_id": stamp.node_tenure_id,
                        "workspace_id": stamp.workspace_id,
                        "channel_kind": "internal",
                        "active": True,
                        "created_at": manifest.provisioned_at,
                        "generation": 1,
                    },
                ),
            )
            after = _exact_state(connection, stamp, manifest)
            if after != ("active", ("active", 1), (True, 1)):
                raise RealmProvisioningError("synthetic owner setup verification failed")
            replayed = not any(inserted)
        else:
            if before == ("disabled", ("revoked", 2), (False, 2)):
                replayed = True
            elif before != ("active", ("active", 1), (True, 1)):
                raise RealmProvisioningError("synthetic owner is not exactly revocable")
            else:
                connection.execute(
                    "UPDATE lucy.node_memberships SET status='revoked',generation=2 WHERE id=%s",
                    (manifest.membership_id,),
                )
                connection.execute(
                    "UPDATE lucy.channel_bindings SET active=false,generation=2 WHERE id=%s",
                    (manifest.channel_binding_id,),
                )
                connection.execute(
                    "UPDATE lucy.principals SET status='disabled' WHERE id=%s",
                    (manifest.principal_id,),
                )
                if _exact_state(connection, stamp, manifest) != (
                    "disabled",
                    ("revoked", 2),
                    (False, 2),
                ):
                    raise RealmProvisioningError("synthetic owner revocation verification failed")
                replayed = False
        return {
            "contract": "lucy.synthetic-owner-commission.v1.3",
            "status": "passed",
            "action": action,
            "realm_slug": stamp.realm_slug,
            "manifest_digest": manifest.digest_hex(),
            "runtime_admission": "quarantined",
            "capture_enabled": False,
            "replayed": replayed,
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("setup", "revoke"))
    args = parser.parse_args()
    try:
        report = run(SyntheticOwnerConfig.from_environment(), args.action)
    except Exception as exc:
        print(
            json.dumps(
                {
                    "contract": "lucy.synthetic-owner-commission.v1.3",
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
