"""Stage one synthetic revocation and one cost reservation for the R1 drill.

This operator-only command deliberately stops before journal append. It uses the
offline migration identity only to assume each existing function-owner role for
one explicit transaction, then closes the connection. Deployed writer and
acknowledgement services must perform all later persistence operations.
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
    _conninfo,
    _database_url,
    _required,
)
from deploy.postgres.provision_recovery_drill_fixture_v1_3 import (
    RecoveryDrillFixtureManifestV1,
    _policy_for,
)
from lucy.contracts.canonical import canonical_sha256
from lucy.cost_admission import ProviderAttemptAdmissionV1, ProviderAttemptRequestV1
from lucy.readiness import R1_SCHEMA_REVISION
from lucy.realm_provisioning import RealmSecurityStampV1
from lucy.recovery_journal import RecoveryStreamBindingV1, RecoveryStreamKind

AUTHORIZATION = "security-v1.3-stage-synthetic-recovery-events"
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_SAFE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+=-]*\Z")
_PREFIX = b"LUCY-R1-RECOVERY-DRILL-EVENTS-V1\0"


class RecoveryDrillEventManifestV1(BaseModel):
    """Reviewed identifiers and commitments for the two post-target events."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["1"] = "1"
    object_type: Literal["lucy.r1-recovery-drill-events.v1"] = (
        "lucy.r1-recovery-drill-events.v1"
    )
    realm_slug: str = Field(pattern=r"^[a-z][a-z0-9-]{0,30}$")
    fixture_manifest_digest: str
    authority_idempotency_key: str
    source_authority_ref: str
    attempt_id: UUID
    cost_idempotency_key: str
    request_commitment: str
    session_commitment: str
    ip_commitment: str
    requested_at: datetime

    @model_validator(mode="after")
    def content_free_event_boundary_is_exact(self) -> Self:
        strings = (
            self.authority_idempotency_key,
            self.source_authority_ref,
            self.cost_idempotency_key,
        )
        digests = (
            self.fixture_manifest_digest,
            self.request_commitment,
            self.session_commitment,
            self.ip_commitment,
        )
        if (
            any(_SAFE.fullmatch(value) is None for value in strings)
            or not self.authority_idempotency_key.startswith("synthetic:recovery:authority:")
            or not self.cost_idempotency_key.startswith("synthetic:recovery:cost:")
            or not self.source_authority_ref.startswith("operator:synthetic-recovery:")
            or any(_DIGEST.fullmatch(value) is None for value in digests)
            or self.requested_at.utcoffset() is None
        ):
            raise ValueError("recovery drill event manifest is outside the synthetic boundary")
        return self

    def digest_hex(self) -> str:
        return canonical_sha256(self.model_dump(mode="python"), prefix=_PREFIX)


class RecoveryDrillEventConfig(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True, frozen=True)

    migration_url: Any
    stamp: RealmSecurityStampV1
    fixture: RecoveryDrillFixtureManifestV1
    events: RecoveryDrillEventManifestV1
    authority_binding: RecoveryStreamBindingV1
    binding_manifest_digest: str

    @classmethod
    def from_environment(
        cls, environment: Mapping[str, str] | None = None
    ) -> RecoveryDrillEventConfig:
        values = os.environ if environment is None else environment
        if values.get("RENDER") != "true" or values.get("LUCY_ENVIRONMENT") != "production":
            raise RealmProvisioningError("recovery event staging requires production Render")
        if values.get("LUCY_TRANSCRIPT_CAPTURE_ENABLED") != "false":
            raise RealmProvisioningError("transcript capture must remain disabled")
        if values.get("LUCY_RECOVERY_DRILL_EVENT_AUTHORIZATION") != AUTHORIZATION:
            raise RealmProvisioningError("exact recovery event authorization is required")
        migration_url = _database_url(_required(values, "LUCY_MIGRATION_DATABASE_URL"))
        if (
            migration_url.username != "lucy_migration"
            or migration_url.host is None
            or _PRIVATE_RENDER_HOST.fullmatch(migration_url.host) is None
            or migration_url.database is None
            or _LUCY_DATABASE.fullmatch(migration_url.database) is None
            or migration_url.port not in (None, 5432)
        ):
            raise RealmProvisioningError("event staging requires private migration login")
        try:
            stamp = RealmSecurityStampV1.model_validate_json(
                _required(values, "LUCY_REALM_SECURITY_STAMP_JSON")
            )
            fixture = RecoveryDrillFixtureManifestV1.model_validate_json(
                _required(values, "LUCY_RECOVERY_DRILL_FIXTURE_MANIFEST_JSON")
            )
            events = RecoveryDrillEventManifestV1.model_validate_json(
                _required(values, "LUCY_RECOVERY_DRILL_EVENT_MANIFEST_JSON")
            )
            authority_binding = RecoveryStreamBindingV1.model_validate_json(
                _required(values, "LUCY_AUTHORITY_RECOVERY_STREAM_BINDING_JSON")
            )
        except (ValidationError, ValueError) as exc:
            raise RealmProvisioningError("recovery event staging input is invalid") from exc
        reviewed = _required(values, "LUCY_RECOVERY_DRILL_EVENT_MANIFEST_SHA256")
        stamp_digest = _required(values, "LUCY_REALM_SECURITY_STAMP_SHA256")
        binding_manifest_digest = _required(
            values, "LUCY_RECOVERY_BINDING_MANIFEST_DIGEST"
        )
        if (
            _DIGEST.fullmatch(reviewed) is None
            or reviewed != events.digest_hex()
            or _DIGEST.fullmatch(stamp_digest) is None
            or stamp_digest != stamp.digest_hex()
            or _DIGEST.fullmatch(binding_manifest_digest) is None
            or authority_binding.binding_manifest_digest != binding_manifest_digest
        ):
            raise RealmProvisioningError("recovery event manifest digest does not match")
        if (
            stamp.realm_slug != fixture.realm_slug
            or stamp.realm_slug != events.realm_slug
            or events.fixture_manifest_digest != fixture.digest_hex()
            or authority_binding.stream_kind is not RecoveryStreamKind.AUTHORITY
        ):
            raise RealmProvisioningError("recovery event scope differs")
        return cls(
            migration_url=migration_url,
            stamp=stamp,
            fixture=fixture,
            events=events,
            authority_binding=authority_binding,
            binding_manifest_digest=binding_manifest_digest,
        )


def _verify_boundary(connection: psycopg.Connection[Any]) -> None:
    row = connection.execute(
        "SELECT current_user,(SELECT version_num FROM public.alembic_version),"
        "(SELECT state FROM lucy.runtime_admission WHERE singleton),"
        "lucy.capture_boundary_safe_v1(),"
        "(SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid())"
    ).fetchone()
    if row != ("lucy_migration", R1_SCHEMA_REVISION, "quarantined", True, True):
        raise RealmProvisioningError("recovery event database boundary differs")


def _verify_fixture(connection: psycopg.Connection[Any], config: RecoveryDrillEventConfig) -> None:
    fixture, stamp, events = config.fixture, config.stamp, config.events
    policy = _policy_for(fixture, stamp)
    row = connection.execute(
        "SELECT EXISTS(SELECT 1 FROM lucy.node_memberships WHERE id=%s "
        "AND principal_id=%s AND workspace_id=%s AND role='owner' AND status='active' "
        "AND generation=1),EXISTS(SELECT 1 FROM lucy.channel_bindings WHERE id=%s "
        "AND node_id=%s AND tenure_id=%s AND workspace_id=%s AND channel_kind='website_public' "
        "AND hostname=%s AND active AND generation=1),EXISTS(SELECT 1 FROM "
        "lucy.provider_cost_policies_v1 WHERE id=%s AND version=1 AND node_id=%s "
        "AND channel_binding_id=%s AND policy_digest=%s)",
        (
            fixture.owner_membership_id,
            fixture.owner_principal_id,
            stamp.workspace_id,
            fixture.channel_binding_id,
            stamp.node_id,
            stamp.node_tenure_id,
            stamp.workspace_id,
            fixture.hostname,
            fixture.policy_id,
            stamp.node_id,
            fixture.channel_binding_id,
            policy.digest_hex(),
        ),
    ).fetchone()
    member = connection.execute(
        "SELECT EXISTS(SELECT 1 FROM lucy.node_memberships m WHERE m.id=%s "
        "AND m.principal_id=%s AND m.workspace_id=%s AND m.role='member' AND "
        "((m.status='active' AND m.generation=1) OR (m.status='revoked' AND "
        "m.generation=2 AND EXISTS(SELECT 1 FROM lucy.authority_transition_events_v1 e "
        "WHERE e.idempotency_key=%s AND e.event_type='membership_revoked' "
        "AND e.subject_id=m.id AND e.actor_id=%s AND e.stream_id=%s "
        "AND e.authority_epoch=%s AND e.source_authority_ref=%s "
        "AND e.source_authority_digest=%s AND e.previous_generation=1 "
        "AND e.new_generation=2))))",
        (
            fixture.member_membership_id,
            fixture.member_principal_id,
            stamp.workspace_id,
            events.authority_idempotency_key,
            fixture.owner_principal_id,
            config.authority_binding.stream_id,
            config.authority_binding.authority_epoch,
            events.source_authority_ref,
            events.fixture_manifest_digest,
        ),
    ).fetchone()
    if row != (True, True, True) or member != (True,):
        raise RealmProvisioningError("pre-target recovery fixture differs")


def _stage_authority(config: RecoveryDrillEventConfig) -> Mapping[str, Any]:
    fixture, events, binding = config.fixture, config.events, config.authority_binding
    with psycopg.connect(_conninfo(config.migration_url)) as connection:
        connection.execute("SET LOCAL lock_timeout = '15s'")
        connection.execute("SET LOCAL statement_timeout = '120s'")
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (_MAINTENANCE_LOCK,))
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (_ADMISSION_LOCK,))
        _verify_boundary(connection)
        _verify_fixture(connection, config)
        connection.execute("SET LOCAL ROLE lucy_authority_function_owner")
        row = connection.execute(
            "SELECT lucy.stage_membership_revocation_v1(%s,%s,%s,%s,%s,%s,%s)",
            (
                fixture.member_membership_id,
                fixture.owner_principal_id,
                binding.stream_id,
                binding.authority_epoch,
                events.authority_idempotency_key,
                events.source_authority_ref,
                events.fixture_manifest_digest,
            ),
        ).fetchone()
        if row is None or not isinstance(row[0], dict):
            raise RealmProvisioningError("synthetic authority event was not staged")
        result: Mapping[str, Any] = row[0]
    return result


def _stage_cost(config: RecoveryDrillEventConfig) -> ProviderAttemptAdmissionV1:
    fixture, events, stamp = config.fixture, config.events, config.stamp
    request = ProviderAttemptRequestV1(
        attempt_id=events.attempt_id,
        idempotency_key=events.cost_idempotency_key,
        node_id=stamp.node_id,
        channel_binding_id=fixture.channel_binding_id,
        provider=fixture.provider,
        model=fixture.model,
        rate_version=fixture.rate_version,
        request_commitment=events.request_commitment,
        session_commitment=events.session_commitment,
        ip_commitment=events.ip_commitment,
        maximum_microusd=1,
        input_tokens=1,
        output_tokens=1,
        request_bytes=1,
        timeout_seconds=1,
        requested_at=events.requested_at,
    )
    with psycopg.connect(_conninfo(config.migration_url)) as connection:
        connection.execute("SET LOCAL lock_timeout = '15s'")
        connection.execute("SET LOCAL statement_timeout = '120s'")
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (_MAINTENANCE_LOCK,))
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (_ADMISSION_LOCK,))
        _verify_boundary(connection)
        _verify_fixture(connection, config)
        connection.execute("SET LOCAL ROLE lucy_cost_function_owner")
        row = connection.execute(
            "SELECT lucy.reserve_provider_attempt_v1("
            "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (
                request.attempt_id,
                request.idempotency_key,
                request.node_id,
                request.channel_binding_id,
                request.provider,
                request.model,
                request.rate_version,
                request.request_commitment,
                request.session_commitment,
                request.ip_commitment,
                request.maximum_microusd,
                request.input_tokens,
                request.output_tokens,
                request.request_bytes,
                request.timeout_seconds,
                request.requested_at,
            ),
        ).fetchone()
        if row is None or not isinstance(row[0], dict):
            raise RealmProvisioningError("synthetic cost event was not staged")
        result = ProviderAttemptAdmissionV1.model_validate(row[0])
    return result


def run(config: RecoveryDrillEventConfig) -> dict[str, object]:
    authority = _stage_authority(config)
    cost = _stage_cost(config)
    if (
        authority.get("state") != "PERSISTENCE_PENDING"
        or authority.get("event_type") != "membership_revoked"
        or str(authority.get("subject_id")) != str(config.fixture.member_membership_id)
        or cost.state != "PERSISTENCE_PENDING"
        or cost.attempt_id != config.events.attempt_id
        or cost.reserved_microusd != 1
        or cost.unresolved_microusd != 1
    ):
        raise RealmProvisioningError("synthetic recovery event result differs")
    return {
        "contract": "lucy.r1-recovery-drill-staging-result.v1",
        "status": "passed",
        "realm_slug": config.events.realm_slug,
        "event_manifest_digest": config.events.digest_hex(),
        "authority_event_id": str(authority["event_id"]),
        "cost_event_id": str(cost.event_id),
        "cost_attempt_id": str(cost.attempt_id),
        "events_persistence": "pending",
        "provider_called": False,
        "runtime_admission": "quarantined",
        "transcript_capture_enabled": False,
    }


def main(argv: Sequence[str] | None = None) -> int:
    if argv:
        raise RealmProvisioningError("recovery event staging accepts no command-line values")
    try:
        report = run(RecoveryDrillEventConfig.from_environment())
    except Exception as exc:
        print(json.dumps({"status": "failed", "error_type": type(exc).__name__}))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
