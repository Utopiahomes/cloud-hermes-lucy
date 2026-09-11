"""Provision immutable, content-free prerequisites for the R1 recovery drill.

The fixture is created before the selected PITR target. It contains only synthetic
identities, an unreachable ``.invalid`` public channel, and a disabled-by-runtime
cost policy. It never stages a recovery event or invokes a model provider.
"""

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
    _check_foundation,
    _conninfo,
    _database_url,
    _insert_exact,
    _required,
)
from lucy.contracts.canonical import canonical_sha256
from lucy.cost_admission import ProviderCostPolicyV1
from lucy.readiness import R1_SCHEMA_REVISION
from lucy.realm_provisioning import RealmSecurityStampV1

AUTHORIZATION = "security-v1.3-synthetic-recovery-fixture"
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_SAFE = re.compile(r"[a-z0-9][a-z0-9-]{0,79}\Z")
_HOSTNAME = re.compile(r"synthetic-recovery-[a-z0-9-]{1,220}\.invalid\Z")
_PREFIX = b"LUCY-R1-RECOVERY-DRILL-FIXTURE-V1\0"


class RecoveryDrillFixtureManifestV1(BaseModel):
    """Reviewed identifiers for a synthetic pre-restore fixture."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["1"] = "1"
    object_type: Literal["lucy.r1-recovery-drill-fixture.v1"] = (
        "lucy.r1-recovery-drill-fixture.v1"
    )
    realm_slug: str = Field(pattern=r"^[a-z][a-z0-9-]{0,30}$")
    owner_principal_id: UUID
    owner_membership_id: UUID
    member_principal_id: UUID
    member_membership_id: UUID
    channel_binding_id: UUID
    policy_id: UUID
    identity_issuer: str
    owner_subject: str
    member_subject: str
    hostname: str
    provider: Literal["openrouter"] = "openrouter"
    model: Literal["openai/gpt-oss-20b"] = "openai/gpt-oss-20b"
    rate_version: Literal["synthetic-recovery-v1"] = "synthetic-recovery-v1"
    provisioned_at: datetime

    @model_validator(mode="after")
    def synthetic_boundary_is_exact(self) -> Self:
        identifiers = (
            self.owner_principal_id,
            self.owner_membership_id,
            self.member_principal_id,
            self.member_membership_id,
            self.channel_binding_id,
            self.policy_id,
        )
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("recovery fixture identifiers must be distinct")
        if (
            self.identity_issuer != f"lucy://synthetic-recovery/{self.realm_slug}"
            or _SAFE.fullmatch(self.owner_subject) is None
            or _SAFE.fullmatch(self.member_subject) is None
            or not self.owner_subject.startswith("synthetic-recovery-owner-")
            or not self.member_subject.startswith("synthetic-recovery-member-")
            or self.owner_subject == self.member_subject
            or _HOSTNAME.fullmatch(self.hostname) is None
            or self.provisioned_at.utcoffset() is None
        ):
            raise ValueError("recovery fixture is outside the synthetic boundary")
        return self

    def digest_hex(self) -> str:
        return canonical_sha256(self.model_dump(mode="python"), prefix=_PREFIX)


class RecoveryDrillFixtureConfig(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True, frozen=True)

    migration_url: Any
    stamp: RealmSecurityStampV1
    manifest: RecoveryDrillFixtureManifestV1

    @classmethod
    def from_environment(
        cls, environment: Mapping[str, str] | None = None
    ) -> RecoveryDrillFixtureConfig:
        values = os.environ if environment is None else environment
        if values.get("RENDER") != "true" or values.get("LUCY_ENVIRONMENT") != "production":
            raise RealmProvisioningError("recovery fixture requires production Render")
        if values.get("LUCY_TRANSCRIPT_CAPTURE_ENABLED") != "false":
            raise RealmProvisioningError("transcript capture must remain disabled")
        if values.get("LUCY_RECOVERY_DRILL_FIXTURE_AUTHORIZATION") != AUTHORIZATION:
            raise RealmProvisioningError("exact recovery fixture authorization is required")
        migration_url = _database_url(_required(values, "LUCY_MIGRATION_DATABASE_URL"))
        if (
            migration_url.username != "lucy_migration"
            or migration_url.host is None
            or _PRIVATE_RENDER_HOST.fullmatch(migration_url.host) is None
            or migration_url.database is None
            or _LUCY_DATABASE.fullmatch(migration_url.database) is None
            or migration_url.port not in (None, 5432)
        ):
            raise RealmProvisioningError("recovery fixture requires private migration login")
        try:
            stamp = RealmSecurityStampV1.model_validate_json(
                _required(values, "LUCY_REALM_SECURITY_STAMP_JSON")
            )
            manifest = RecoveryDrillFixtureManifestV1.model_validate_json(
                _required(values, "LUCY_RECOVERY_DRILL_FIXTURE_MANIFEST_JSON")
            )
        except (ValidationError, ValueError) as exc:
            raise RealmProvisioningError("recovery fixture input is invalid") from exc
        for name, actual in (
            ("LUCY_REALM_SECURITY_STAMP_SHA256", stamp.digest_hex()),
            ("LUCY_RECOVERY_DRILL_FIXTURE_MANIFEST_SHA256", manifest.digest_hex()),
        ):
            reviewed = _required(values, name)
            if _DIGEST.fullmatch(reviewed) is None or reviewed != actual:
                raise RealmProvisioningError("recovery fixture digest does not match")
        if manifest.realm_slug != stamp.realm_slug:
            raise RealmProvisioningError("recovery fixture realm differs")
        return cls(migration_url=migration_url, stamp=stamp, manifest=manifest)


def _policy_for(
    manifest: RecoveryDrillFixtureManifestV1, stamp: RealmSecurityStampV1
) -> ProviderCostPolicyV1:
    return ProviderCostPolicyV1(
        policy_id=manifest.policy_id,
        version=1,
        node_id=stamp.node_id,
        channel_binding_id=manifest.channel_binding_id,
        provider=manifest.provider,
        model=manifest.model,
        rate_version=manifest.rate_version,
        effective_at=manifest.provisioned_at,
        kill_state="enabled",
        platform_daily_cap_microusd=1_000,
        node_daily_cap_microusd=1_000,
        site_daily_cap_microusd=1_000,
        provider_daily_cap_microusd=1_000,
        outstanding_cap_microusd=1_000,
        concurrency_limit=1,
        requests_per_minute=1,
        session_requests_per_minute=1,
        ip_requests_per_minute=1,
        per_request_cap_microusd=1,
        max_input_tokens=1,
        max_output_tokens=1,
        max_request_bytes=1,
        timeout_seconds=1,
    )


def _policy(config: RecoveryDrillFixtureConfig) -> ProviderCostPolicyV1:
    return _policy_for(config.manifest, config.stamp)


def run(config: RecoveryDrillFixtureConfig) -> dict[str, object]:
    stamp, manifest = config.stamp, config.manifest
    policy = _policy(config)
    with psycopg.connect(_conninfo(config.migration_url)) as connection:
        connection.execute("SET LOCAL lock_timeout = '15s'")
        connection.execute("SET LOCAL statement_timeout = '120s'")
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (_MAINTENANCE_LOCK,))
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (_ADMISSION_LOCK,))
        identity = connection.execute(
            "SELECT current_user,(SELECT version_num FROM public.alembic_version),"
            "(SELECT state FROM lucy.runtime_admission WHERE singleton),"
            "lucy.capture_boundary_safe_v1(),"
            "(SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid())"
        ).fetchone()
        if identity != ("lucy_migration", R1_SCHEMA_REVISION, "quarantined", True, True):
            raise RealmProvisioningError("recovery fixture database boundary differs")
        _check_foundation(connection, stamp)
        inserted = [
            _insert_exact(
                connection,
                "principals",
                "id",
                {
                    "id": manifest.owner_principal_id,
                    "issuer": manifest.identity_issuer,
                    "subject": manifest.owner_subject,
                    "principal_kind": "human",
                    "display_name": "Synthetic recovery owner",
                    "created_at": manifest.provisioned_at,
                    "status": "active",
                },
            ),
            _insert_exact(
                connection,
                "principals",
                "id",
                {
                    "id": manifest.member_principal_id,
                    "issuer": manifest.identity_issuer,
                    "subject": manifest.member_subject,
                    "principal_kind": "human",
                    "display_name": "Synthetic recovery member",
                    "created_at": manifest.provisioned_at,
                    "status": "active",
                },
            ),
            _insert_exact(
                connection,
                "node_memberships",
                "id",
                {
                    "id": manifest.owner_membership_id,
                    "principal_id": manifest.owner_principal_id,
                    "workspace_id": stamp.workspace_id,
                    "role": "owner",
                    "status": "active",
                    "granted_at": manifest.provisioned_at,
                    "generation": 1,
                },
            ),
            _insert_exact(
                connection,
                "node_memberships",
                "id",
                {
                    "id": manifest.member_membership_id,
                    "principal_id": manifest.member_principal_id,
                    "workspace_id": stamp.workspace_id,
                    "role": "member",
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
                    "channel_kind": "website_public",
                    "active": True,
                    "created_at": manifest.provisioned_at,
                    "generation": 1,
                },
            ),
        ]
        policy_values = policy.model_dump(mode="python") | {
            "policy_digest": policy.digest_hex(),
            "created_at": manifest.provisioned_at,
        }
        policy_values["id"] = policy_values.pop("policy_id")
        inserted.append(
            _insert_exact(connection, "provider_cost_policies_v1", "id", policy_values)
        )
        if any(inserted) and not all(inserted):
            raise RealmProvisioningError("recovery fixture was only partially absent")
        anchor = connection.execute("SELECT clock_timestamp()").fetchone()
        if anchor is None:
            raise RealmProvisioningError("recovery fixture anchor time is unavailable")
    return {
        "contract": "lucy.r1-recovery-drill-fixture-result.v1",
        "status": "passed",
        "realm_slug": manifest.realm_slug,
        "manifest_digest": manifest.digest_hex(),
        "policy_digest": policy.digest_hex(),
        "restore_anchor_at": anchor[0].isoformat(),
        "replayed": not any(inserted),
        "runtime_admission": "quarantined",
        "transcript_capture_enabled": False,
        "provider_called": False,
    }


def main(argv: Sequence[str] | None = None) -> int:
    if argv:
        raise RealmProvisioningError("recovery fixture accepts no command-line values")
    try:
        report = run(RecoveryDrillFixtureConfig.from_environment())
    except Exception as exc:
        print(json.dumps({"status": "failed", "error_type": type(exc).__name__}))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
