"""Commission one digest-pinned public projection while runtime admission is closed.

This command is intended for an ephemeral production Render job. It accepts the
migration-owner URL and an identifier-only manifest through environment variables,
emits no credentials or projection content, and is exactly replayable.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any, Literal
from uuid import UUID

import psycopg
from pydantic import BaseModel, ConfigDict, field_validator
from sqlalchemy.engine import URL, make_url

from lucy.publication import snapshot_digest
from lucy.readiness import ADMISSION_LOCK, STAGE2_SCHEMA_REVISION

AUTHORIZATION = "utopia-public-projection-v1-production"
MAINTENANCE_LOCK = 0x4C5543594D53
_PRIVATE_RENDER_HOST = re.compile(r"dpg-[a-z0-9-]+-a\Z")
_LUCY_DATABASE = re.compile(r"lucy(?:_[a-z0-9]+)*\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")


class PublicProjectionCommissionError(RuntimeError):
    """The public projection commissioning boundary was not satisfied."""


class PublicProjectionCommissionManifestV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract: str = "lucy.utopia.public-projection-commission.v1"
    source_commit: str
    schema_revision: str
    decision_id: str
    realm_slug: str
    node_id: UUID
    tenure_id: UUID
    security_realm_id: UUID
    realm_binding_id: UUID
    storage_epoch: UUID
    expected_runtime_admission: Literal["quarantined", "ready"]
    workspace_id: UUID
    workspace_slug: str
    channel_binding_id: UUID
    hostname: str
    publisher_principal_id: UUID
    publisher_membership_id: UUID
    publisher_issuer: str
    publisher_subject: str
    approver_principal_id: UUID
    approver_membership_id: UUID
    approver_issuer: str
    approver_subject: str
    candidate_id: UUID
    approval_id: UUID
    version_id: UUID
    staged_event_id: UUID
    approved_event_id: UUID
    published_event_id: UUID
    snapshot_digest: str
    provisioned_at: datetime

    @field_validator("source_commit")
    @classmethod
    def validate_commit(cls, value: str) -> str:
        if _COMMIT.fullmatch(value) is None:
            raise ValueError("source commit must be a lowercase Git object ID")
        return value

    @field_validator("snapshot_digest")
    @classmethod
    def validate_digest(cls, value: str) -> str:
        if _DIGEST.fullmatch(value) is None:
            raise ValueError("snapshot digest must be lowercase SHA-256")
        return value

    def digest_hex(self) -> str:
        payload = self.model_dump(mode="json")
        encoded = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
        return hashlib.sha256(encoded).hexdigest()


class PublicProjectionCommissionConfig(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True, frozen=True)

    migration_url: URL
    manifest: PublicProjectionCommissionManifestV1
    snapshot: dict[str, Any]

    @classmethod
    def from_environment(
        cls, environment: Mapping[str, str] | None = None
    ) -> PublicProjectionCommissionConfig:
        values = os.environ if environment is None else environment
        if values.get("RENDER") != "true" or values.get("LUCY_ENVIRONMENT") != "production":
            raise PublicProjectionCommissionError(
                "commissioning requires the production Render runtime"
            )
        if values.get("LUCY_TRANSCRIPT_CAPTURE_ENABLED") != "false":
            raise PublicProjectionCommissionError(
                "the commissioning utility must not capture transcripts"
            )
        if values.get("LUCY_PUBLIC_PROJECTION_AUTHORIZATION") != AUTHORIZATION:
            raise PublicProjectionCommissionError(
                "the exact public projection authorization is required"
            )
        migration_url = _database_url(_required(values, "LUCY_MIGRATION_DATABASE_URL"))
        if migration_url.username != "lucy_migration":
            raise PublicProjectionCommissionError("the migration URL must use lucy_migration")
        if (
            migration_url.host is None
            or _PRIVATE_RENDER_HOST.fullmatch(migration_url.host) is None
            or migration_url.database is None
            or _LUCY_DATABASE.fullmatch(migration_url.database) is None
            or migration_url.port not in (None, 5432)
        ):
            raise PublicProjectionCommissionError(
                "the migration URL must target the private Lucy database"
            )
        try:
            manifest = PublicProjectionCommissionManifestV1.model_validate_json(
                _required(values, "LUCY_PUBLIC_PROJECTION_MANIFEST_JSON")
            )
        except Exception as exc:
            raise PublicProjectionCommissionError(
                "the public projection manifest is invalid"
            ) from exc
        if manifest.digest_hex() != _required(
            values, "LUCY_PUBLIC_PROJECTION_MANIFEST_SHA256"
        ):
            raise PublicProjectionCommissionError(
                "the public projection manifest digest does not match"
            )
        if manifest.schema_revision != STAGE2_SCHEMA_REVISION:
            raise PublicProjectionCommissionError("the manifest schema revision differs")
        if manifest.realm_slug != "utopia" or manifest.hostname != "www.utopiahomes.com":
            raise PublicProjectionCommissionError("the public scope differs")
        if (
            manifest.workspace_slug != "utopia-public-website"
            or manifest.publisher_issuer != "lucy://utopia/public-projection"
            or manifest.publisher_subject != "publisher-v1"
            or manifest.approver_issuer != "lucy://utopia/public-projection"
            or manifest.approver_subject != "approver-v1"
            or manifest.publisher_principal_id == manifest.approver_principal_id
        ):
            raise PublicProjectionCommissionError("the publication authority differs")
        projection_path = Path(
            _required(values, "LUCY_PUBLIC_PROJECTION_SNAPSHOT_PATH")
        ).resolve()
        root = Path(__file__).resolve().parents[2]
        expected_path = (root / "deploy/render/utopia-public-projection.v0.json").resolve()
        if projection_path != expected_path:
            raise PublicProjectionCommissionError("the projection path differs")
        try:
            snapshot = json.loads(projection_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise PublicProjectionCommissionError("the projection payload is invalid") from exc
        if (
            not isinstance(snapshot, dict)
            or snapshot.get("schema") != "lucy-public-faq-v1"
            or not isinstance(snapshot.get("faqs"), list)
            or len(snapshot["faqs"]) != 8
            or snapshot_digest(snapshot) != manifest.snapshot_digest
        ):
            raise PublicProjectionCommissionError("the reviewed projection digest differs")
        return cls(migration_url=migration_url, manifest=manifest, snapshot=snapshot)


def _required(values: Mapping[str, str], name: str) -> str:
    value = values.get(name, "").strip()
    if not value:
        raise PublicProjectionCommissionError(f"missing required configuration: {name}")
    return value


def _database_url(raw: str) -> URL:
    try:
        parsed = make_url(raw)
    except Exception as exc:
        raise PublicProjectionCommissionError("invalid PostgreSQL URL") from exc
    if (
        parsed.drivername not in {"postgresql", "postgresql+psycopg"}
        or not parsed.username
        or not parsed.password
        or not parsed.host
        or not parsed.database
    ):
        raise PublicProjectionCommissionError("database URL is incomplete")
    return parsed.set(drivername="postgresql+psycopg").update_query_dict(
        {"sslmode": "require"}
    )


def _conninfo(url: URL) -> str:
    return url.set(drivername="postgresql").render_as_string(hide_password=False)


def _one(connection: psycopg.Connection[Any], query: str, params: tuple[Any, ...] = ()) -> Any:
    row = connection.execute(query, params).fetchone()
    if row is None:
        raise PublicProjectionCommissionError("database boundary row is unavailable")
    return row[0]


def _insert_principal(
    connection: psycopg.Connection[Any], *, principal_id: UUID, issuer: str, subject: str,
    display_name: str
) -> None:
    connection.execute(
        "INSERT INTO lucy.principals(id,issuer,subject,principal_kind,display_name,created_at) "
        "VALUES(%s,%s,%s,'service',%s,now()) ON CONFLICT(issuer,subject) DO NOTHING",
        (principal_id, issuer, subject, display_name),
    )
    row = connection.execute(
        "SELECT id,principal_kind,display_name FROM lucy.principals "
        "WHERE issuer=%s AND subject=%s",
        (issuer, subject),
    ).fetchone()
    if row != (principal_id, "service", display_name):
        raise PublicProjectionCommissionError("publication principal conflicts")


def _insert_membership(
    connection: psycopg.Connection[Any], *, membership_id: UUID, principal_id: UUID,
    workspace_id: UUID, role: str
) -> None:
    connection.execute(
        "INSERT INTO lucy.node_memberships"
        "(id,principal_id,workspace_id,role,status,granted_at) "
        "VALUES(%s,%s,%s,%s,'active',now()) "
        "ON CONFLICT(principal_id,workspace_id) DO NOTHING",
        (membership_id, principal_id, workspace_id, role),
    )
    row = connection.execute(
        "SELECT id,role,status FROM lucy.node_memberships "
        "WHERE principal_id=%s AND workspace_id=%s",
        (principal_id, workspace_id),
    ).fetchone()
    if row != (membership_id, role, "active"):
        raise PublicProjectionCommissionError("publication membership conflicts")


def _verify_boundary(
    connection: psycopg.Connection[Any], manifest: PublicProjectionCommissionManifestV1
) -> None:
    row = connection.execute(
        "SELECT current_user,"
        "(SELECT version_num FROM public.alembic_version),"
        "(SELECT state FROM lucy.runtime_admission WHERE singleton),"
        "(SELECT storage_epoch FROM lucy.runtime_admission WHERE singleton),"
        "(SELECT state FROM lucy.lifecycle WHERE singleton),"
        "(SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid())"
    ).fetchone()
    if row != (
        "lucy_migration",
        manifest.schema_revision,
        manifest.expected_runtime_admission,
        manifest.storage_epoch,
        "ready",
        True,
    ):
        raise PublicProjectionCommissionError("production database boundary differs")
    realm = connection.execute(
        "SELECT n.id,t.id,r.id,b.id FROM lucy.nodes n "
        "JOIN lucy.node_tenures t ON t.node_id=n.id AND t.ends_at IS NULL "
        "JOIN lucy.realm_bindings b ON b.tenure_id=t.id AND b.valid_to IS NULL "
        "JOIN lucy.security_realms r ON r.id=b.realm_id "
        "WHERE n.slug=%s AND r.slug=%s",
        (manifest.realm_slug, manifest.realm_slug),
    ).fetchone()
    if realm != (
        manifest.node_id,
        manifest.tenure_id,
        manifest.security_realm_id,
        manifest.realm_binding_id,
    ):
        raise PublicProjectionCommissionError("reviewed realm binding differs")
    public_role = connection.execute(
        "SELECT rolcanlogin,rolsuper,rolinherit FROM pg_roles WHERE rolname='lucy_utopia_public'"
    ).fetchone()
    if public_role != (True, False, False):
        raise PublicProjectionCommissionError("public database login boundary differs")
    if _one(
        connection,
        "SELECT has_function_privilege('lucy_utopia_public',"
        "'lucy.public_projection_answer_v2(text,text,uuid)','EXECUTE')",
    ) is not True:
        raise PublicProjectionCommissionError("public answer grant is unavailable")
    direct_grants = connection.execute(
        "SELECT table_name,privilege_type FROM information_schema.role_table_grants "
        "WHERE grantee='lucy_utopia_public' AND table_schema='lucy' "
        "ORDER BY table_name,privilege_type"
    ).fetchall()
    if direct_grants != [("lifecycle", "SELECT"), ("runtime_admission", "SELECT")]:
        raise PublicProjectionCommissionError("public login table authority differs")


def _apply(
    connection: psycopg.Connection[Any], config: PublicProjectionCommissionConfig
) -> bool:
    manifest = config.manifest
    active = connection.execute(
        "SELECT v.id,v.version,v.snapshot_digest FROM lucy.channel_bindings c "
        "LEFT JOIN lucy.public_projection_routes r ON r.channel_binding_id=c.id "
        "LEFT JOIN lucy.public_projection_versions v ON v.id=r.active_version_id "
        "WHERE c.hostname=%s",
        (manifest.hostname,),
    ).fetchone()
    if active is not None:
        if active != (manifest.version_id, 1, manifest.snapshot_digest):
            raise PublicProjectionCommissionError("an existing public route conflicts")
        return True

    connection.execute(
        "INSERT INTO lucy.workspaces(id,node_id,tenure_id,slug,workspace_kind,created_at) "
        "VALUES(%s,%s,%s,%s,'public_projection',now())",
        (manifest.workspace_id, manifest.node_id, manifest.tenure_id, manifest.workspace_slug),
    )
    _insert_principal(
        connection,
        principal_id=manifest.publisher_principal_id,
        issuer=manifest.publisher_issuer,
        subject=manifest.publisher_subject,
        display_name="Utopia Public Projection Publisher",
    )
    _insert_principal(
        connection,
        principal_id=manifest.approver_principal_id,
        issuer=manifest.approver_issuer,
        subject=manifest.approver_subject,
        display_name="Utopia Public Projection Approver",
    )
    _insert_membership(
        connection,
        membership_id=manifest.publisher_membership_id,
        principal_id=manifest.publisher_principal_id,
        workspace_id=manifest.workspace_id,
        role="publisher",
    )
    _insert_membership(
        connection,
        membership_id=manifest.approver_membership_id,
        principal_id=manifest.approver_principal_id,
        workspace_id=manifest.workspace_id,
        role="approver",
    )
    connection.execute(
        "INSERT INTO lucy.channel_bindings"
        "(id,hostname,node_id,tenure_id,workspace_id,channel_kind,active,created_at) "
        "VALUES(%s,%s,%s,%s,%s,'website_public',true,now())",
        (
            manifest.channel_binding_id,
            manifest.hostname,
            manifest.node_id,
            manifest.tenure_id,
            manifest.workspace_id,
        ),
    )
    connection.execute(
        "INSERT INTO lucy.public_projection_candidates"
        "(id,channel_binding_id,snapshot,snapshot_digest,status,created_by,created_at) "
        "VALUES(%s,%s,%s::jsonb,%s,'draft',%s,now())",
        (
            manifest.candidate_id,
            manifest.channel_binding_id,
            json.dumps(config.snapshot, separators=(",", ":"), ensure_ascii=False),
            manifest.snapshot_digest,
            manifest.publisher_principal_id,
        ),
    )
    connection.execute(
        "INSERT INTO lucy.public_projection_events"
        "(id,channel_binding_id,event_type,candidate_id,version_id,actor_id,occurred_at) "
        "VALUES(%s,%s,'candidate_staged',%s,NULL,%s,now())",
        (
            manifest.staged_event_id,
            manifest.channel_binding_id,
            manifest.candidate_id,
            manifest.publisher_principal_id,
        ),
    )
    connection.execute(
        "INSERT INTO lucy.public_projection_approvals"
        "(id,candidate_id,approved_digest,approved_by,approved_at) "
        "VALUES(%s,%s,%s,%s,now())",
        (
            manifest.approval_id,
            manifest.candidate_id,
            manifest.snapshot_digest,
            manifest.approver_principal_id,
        ),
    )
    connection.execute(
        "UPDATE lucy.public_projection_candidates SET status='approved' WHERE id=%s",
        (manifest.candidate_id,),
    )
    connection.execute(
        "INSERT INTO lucy.public_projection_events"
        "(id,channel_binding_id,event_type,candidate_id,version_id,actor_id,occurred_at) "
        "VALUES(%s,%s,'candidate_approved',%s,NULL,%s,now())",
        (
            manifest.approved_event_id,
            manifest.channel_binding_id,
            manifest.candidate_id,
            manifest.approver_principal_id,
        ),
    )
    connection.execute(
        "INSERT INTO lucy.public_projection_versions"
        "(id,channel_binding_id,candidate_id,version,snapshot,snapshot_digest,published_at) "
        "VALUES(%s,%s,%s,1,%s::jsonb,%s,now())",
        (
            manifest.version_id,
            manifest.channel_binding_id,
            manifest.candidate_id,
            json.dumps(config.snapshot, separators=(",", ":"), ensure_ascii=False),
            manifest.snapshot_digest,
        ),
    )
    connection.execute(
        "INSERT INTO lucy.public_projection_routes"
        "(channel_binding_id,active_version_id,updated_at) "
        "VALUES(%s,%s,now())",
        (manifest.channel_binding_id, manifest.version_id),
    )
    connection.execute(
        "UPDATE lucy.public_projection_candidates SET status='published' WHERE id=%s",
        (manifest.candidate_id,),
    )
    connection.execute(
        "INSERT INTO lucy.public_projection_events"
        "(id,channel_binding_id,event_type,candidate_id,version_id,actor_id,occurred_at) "
        "VALUES(%s,%s,'published',%s,%s,%s,now())",
        (
            manifest.published_event_id,
            manifest.channel_binding_id,
            manifest.candidate_id,
            manifest.version_id,
            manifest.publisher_principal_id,
        ),
    )
    return False


def run(config: PublicProjectionCommissionConfig) -> dict[str, object]:
    with psycopg.connect(_conninfo(config.migration_url)) as connection:
        connection.execute("SET LOCAL lock_timeout = '15s'")
        connection.execute("SET LOCAL statement_timeout = '120s'")
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (MAINTENANCE_LOCK,))
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (ADMISSION_LOCK,))
        _verify_boundary(connection, config.manifest)
        replayed = _apply(connection, config)
        row = connection.execute(
            "SELECT c.channel_kind,c.active,v.version,v.snapshot_digest,"
            "(SELECT count(*) FROM lucy.public_projection_events e "
            " WHERE e.channel_binding_id=c.id) "
            "FROM lucy.channel_bindings c "
            "JOIN lucy.public_projection_routes r ON r.channel_binding_id=c.id "
            "JOIN lucy.public_projection_versions v ON v.id=r.active_version_id "
            "WHERE c.id=%s",
            (config.manifest.channel_binding_id,),
        ).fetchone()
        if row != ("website_public", True, 1, config.manifest.snapshot_digest, 3):
            raise PublicProjectionCommissionError("published projection verification failed")
    return {
        "contract": "lucy.utopia.public-projection-commission-receipt.v1",
        "status": "passed",
        "schema_revision": config.manifest.schema_revision,
        "snapshot_digest": config.manifest.snapshot_digest,
        "faq_count": 8,
        "version": 1,
        "publisher_approver_separated": True,
        "runtime_admission": config.manifest.expected_runtime_admission,
        "replayed": replayed,
    }


def main() -> int:
    try:
        config = PublicProjectionCommissionConfig.from_environment()
        report = run(config)
    except PublicProjectionCommissionError as exc:
        print(
            json.dumps(
                {
                    "contract": "lucy.utopia.public-projection-commission-receipt.v1",
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
                    "contract": "lucy.utopia.public-projection-commission-receipt.v1",
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
