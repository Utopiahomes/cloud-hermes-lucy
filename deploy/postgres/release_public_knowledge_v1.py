"""Stage, approve, or activate one digest-pinned Public Lucy R1 snapshot.

Each invocation performs exactly one release transition. The utility is intended for
an ephemeral production Render job while runtime admission is quarantined. Receipts
contain identifiers and digests only; knowledge content and credentials are never
printed.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal
from uuid import UUID

import psycopg
from pydantic import BaseModel, ConfigDict, field_validator, model_validator
from sqlalchemy.engine import URL, make_url

from lucy.publication import knowledge_snapshot, snapshot_digest
from lucy.readiness import (
    ADMISSION_LOCK,
    MEMORY_IMPORT_SCHEMA_REVISION,
    PUBLIC_CONVERSATION_SCHEMA_REVISION,
)

Action = Literal["stage", "approve", "activate"]

AUTHORIZATIONS: dict[Action, str] = {
    "stage": "utopia-public-knowledge-stage-v1",
    "approve": "utopia-public-knowledge-approve-v1",
    "activate": "utopia-public-knowledge-activate-v1",
}
MAINTENANCE_LOCK = 0x4C5543594D53
SNAPSHOT_RELATIVE_PATH = Path("deploy/render/utopia-public-knowledge.r1.json")
_PRIVATE_RENDER_HOST = re.compile(r"dpg-[a-z0-9-]+-a\Z")
_LUCY_DATABASE = re.compile(r"lucy(?:_[a-z0-9]+)*\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")


class PublicKnowledgeReleaseError(RuntimeError):
    """The exact public-knowledge release boundary was not satisfied."""


class PublicKnowledgeReleaseManifestV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract: Literal["lucy.utopia.public-knowledge-release.v1"] = (
        "lucy.utopia.public-knowledge-release.v1"
    )
    action: Action
    source_commit: str
    schema_revision: str
    decision_id: str
    release_id: UUID
    realm_slug: str
    storage_epoch: UUID
    channel_binding_id: UUID
    hostname: str
    actor_id: UUID
    candidate_id: UUID
    transition_id: UUID
    snapshot_digest: str
    expected_active_version_id: UUID
    expected_active_version: int
    expected_active_digest: str
    approval_id: UUID | None = None
    version_id: UUID | None = None
    authorized_at: datetime

    @field_validator("source_commit")
    @classmethod
    def validate_commit(cls, value: str) -> str:
        if _COMMIT.fullmatch(value) is None:
            raise ValueError("source commit must be a lowercase Git object ID")
        return value

    @field_validator("snapshot_digest", "expected_active_digest")
    @classmethod
    def validate_digest(cls, value: str) -> str:
        if _DIGEST.fullmatch(value) is None:
            raise ValueError("snapshot digests must be lowercase SHA-256")
        return value

    @field_validator("expected_active_version")
    @classmethod
    def validate_version(cls, value: int) -> int:
        if value < 1:
            raise ValueError("the expected active version must be positive")
        return value

    @field_validator("authorized_at")
    @classmethod
    def validate_authorized_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("the authorization timestamp must be timezone-aware")
        return value

    @model_validator(mode="after")
    def validate_action_shape(self) -> PublicKnowledgeReleaseManifestV1:
        if self.realm_slug != "utopia" or self.hostname != "www.utopiahomes.com":
            raise ValueError("the public release scope differs")
        expected_revision = (
            PUBLIC_CONVERSATION_SCHEMA_REVISION
            if self.action == "activate"
            else MEMORY_IMPORT_SCHEMA_REVISION
        )
        if self.schema_revision != expected_revision:
            raise ValueError("the action uses the wrong schema revision")
        if self.action == "stage" and (self.approval_id is not None or self.version_id is not None):
            raise ValueError("staging cannot carry approval or version identifiers")
        if self.action == "approve" and (self.approval_id is None or self.version_id is not None):
            raise ValueError("approval requires only an approval identifier")
        if self.action == "activate" and (self.approval_id is None or self.version_id is None):
            raise ValueError("activation requires approval and version identifiers")
        return self

    def digest_hex(self) -> str:
        encoded = json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode()
        return hashlib.sha256(encoded).hexdigest()


class PublicKnowledgeReleaseConfig(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True, frozen=True)

    migration_url: URL
    manifest: PublicKnowledgeReleaseManifestV1
    snapshot: dict[str, Any]

    @classmethod
    def from_environment(
        cls,
        environment: Mapping[str, str] | None = None,
        *,
        repository_root: Path | None = None,
    ) -> PublicKnowledgeReleaseConfig:
        values = os.environ if environment is None else environment
        if values.get("RENDER") != "true" or values.get("LUCY_ENVIRONMENT") != "production":
            raise PublicKnowledgeReleaseError("release requires the production Render runtime")
        if values.get("LUCY_TRANSCRIPT_CAPTURE_ENABLED") != "false":
            raise PublicKnowledgeReleaseError("the release utility must not capture transcripts")
        try:
            manifest = PublicKnowledgeReleaseManifestV1.model_validate_json(
                _required(values, "LUCY_PUBLIC_KNOWLEDGE_MANIFEST_JSON")
            )
        except Exception as exc:
            raise PublicKnowledgeReleaseError("the public release manifest is invalid") from exc
        if manifest.digest_hex() != _required(values, "LUCY_PUBLIC_KNOWLEDGE_MANIFEST_SHA256"):
            raise PublicKnowledgeReleaseError("the public release manifest digest does not match")
        if values.get("LUCY_PUBLIC_KNOWLEDGE_AUTHORIZATION") != AUTHORIZATIONS[manifest.action]:
            raise PublicKnowledgeReleaseError("the exact action authorization is required")

        migration_url = _database_url(_required(values, "LUCY_MIGRATION_DATABASE_URL"))
        if migration_url.username != "lucy_migration":
            raise PublicKnowledgeReleaseError("the migration URL must use lucy_migration")
        if (
            migration_url.host is None
            or _PRIVATE_RENDER_HOST.fullmatch(migration_url.host) is None
            or migration_url.database is None
            or _LUCY_DATABASE.fullmatch(migration_url.database) is None
            or migration_url.port not in (None, 5432)
        ):
            raise PublicKnowledgeReleaseError(
                "the migration URL must target the private Lucy database"
            )

        root = Path(__file__).resolve().parents[2] if repository_root is None else repository_root
        expected_path = (root / SNAPSHOT_RELATIVE_PATH).resolve()
        supplied_path = Path(_required(values, "LUCY_PUBLIC_KNOWLEDGE_SNAPSHOT_PATH")).resolve()
        if supplied_path != expected_path:
            raise PublicKnowledgeReleaseError("the public knowledge snapshot path differs")
        try:
            raw_snapshot = json.loads(expected_path.read_text(encoding="utf-8"))
            if not isinstance(raw_snapshot, dict) or not isinstance(
                raw_snapshot.get("entries"), list
            ):
                raise ValueError("snapshot shape differs")
            snapshot = knowledge_snapshot(raw_snapshot["entries"])
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            raise PublicKnowledgeReleaseError("the public knowledge snapshot is invalid") from exc
        if snapshot_digest(snapshot) != manifest.snapshot_digest:
            raise PublicKnowledgeReleaseError("the reviewed public knowledge digest differs")
        return cls(migration_url=migration_url, manifest=manifest, snapshot=snapshot)


def _required(values: Mapping[str, str], name: str) -> str:
    value = values.get(name, "").strip()
    if not value:
        raise PublicKnowledgeReleaseError(f"missing required configuration: {name}")
    return value


def _database_url(raw: str) -> URL:
    try:
        parsed = make_url(raw)
    except Exception as exc:
        raise PublicKnowledgeReleaseError("invalid PostgreSQL URL") from exc
    if (
        parsed.drivername not in {"postgresql", "postgresql+psycopg"}
        or not parsed.username
        or not parsed.password
        or not parsed.host
        or not parsed.database
    ):
        raise PublicKnowledgeReleaseError("database URL is incomplete")
    return parsed.set(drivername="postgresql+psycopg").update_query_dict({"sslmode": "require"})


def _conninfo(url: URL) -> str:
    return url.set(drivername="postgresql").render_as_string(hide_password=False)


def _verify_boundary(
    connection: psycopg.Connection[Any], manifest: PublicKnowledgeReleaseManifestV1
) -> None:
    boundary = connection.execute(
        "SELECT current_user,(SELECT version_num FROM public.alembic_version),"
        "(SELECT state FROM lucy.runtime_admission WHERE singleton),"
        "(SELECT storage_epoch FROM lucy.runtime_admission WHERE singleton),"
        "(SELECT state FROM lucy.lifecycle WHERE singleton),"
        "(SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid())"
    ).fetchone()
    if boundary != (
        "lucy_migration",
        manifest.schema_revision,
        "quarantined",
        manifest.storage_epoch,
        "ready",
        True,
    ):
        raise PublicKnowledgeReleaseError("production database boundary differs")

    channel = connection.execute(
        "SELECT c.id,n.slug,c.channel_kind,c.active FROM lucy.channel_bindings c "
        "JOIN lucy.nodes n ON n.id=c.node_id WHERE c.hostname=%s",
        (manifest.hostname,),
    ).fetchone()
    if channel != (manifest.channel_binding_id, manifest.realm_slug, "website_public", True):
        raise PublicKnowledgeReleaseError("the reviewed public channel differs")

    role: Literal["approver", "publisher"] = (
        "approver" if manifest.action == "approve" else "publisher"
    )
    _require_actor(connection, manifest, role)

    if manifest.action == "activate":
        executable = connection.execute(
            "SELECT has_function_privilege('lucy_utopia_public',"
            "'lucy.public_projection_knowledge_v1(text,uuid)','EXECUTE')"
        ).fetchone()
        if executable != (True,):
            raise PublicKnowledgeReleaseError("the public knowledge grant is unavailable")


def _require_actor(
    connection: psycopg.Connection[Any],
    manifest: PublicKnowledgeReleaseManifestV1,
    role: Literal["approver", "publisher"],
) -> None:
    authorized = connection.execute(
        "SELECT count(*) FROM lucy.node_memberships m "
        "JOIN lucy.channel_bindings c ON c.workspace_id=m.workspace_id "
        "WHERE c.id=%s AND m.principal_id=%s AND m.role=%s AND m.status='active'",
        (manifest.channel_binding_id, manifest.actor_id, role),
    ).fetchone()
    if authorized != (1,):
        raise PublicKnowledgeReleaseError("the release actor authority differs")


def _active_route(
    connection: psycopg.Connection[Any], manifest: PublicKnowledgeReleaseManifestV1
) -> tuple[UUID, int, str]:
    row = connection.execute(
        "SELECT v.id,v.version,v.snapshot_digest FROM lucy.public_projection_routes r "
        "JOIN lucy.public_projection_versions v ON v.id=r.active_version_id "
        "WHERE r.channel_binding_id=%s",
        (manifest.channel_binding_id,),
    ).fetchone()
    expected = (
        manifest.expected_active_version_id,
        manifest.expected_active_version,
        manifest.expected_active_digest,
    )
    if row != expected:
        raise PublicKnowledgeReleaseError("the active rollback point differs")
    return expected


def _event_matches(
    connection: psycopg.Connection[Any], manifest: PublicKnowledgeReleaseManifestV1, event: str
) -> bool:
    row = connection.execute(
        "SELECT channel_binding_id,event_type,candidate_id,version_id,actor_id "
        "FROM lucy.public_projection_events WHERE id=%s",
        (manifest.transition_id,),
    ).fetchone()
    if row is None:
        return False
    if row != (
        manifest.channel_binding_id,
        event,
        manifest.candidate_id,
        manifest.version_id if event == "published" else None,
        manifest.actor_id,
    ):
        raise PublicKnowledgeReleaseError("the release transition identifier conflicts")
    return True


def _stage(
    connection: psycopg.Connection[Any], config: PublicKnowledgeReleaseConfig
) -> bool:
    manifest = config.manifest
    _require_actor(connection, manifest, "publisher")
    existing = connection.execute(
        "SELECT channel_binding_id,snapshot,snapshot_digest,status,created_by "
        "FROM lucy.public_projection_candidates WHERE id=%s",
        (manifest.candidate_id,),
    ).fetchone()
    if existing is not None:
        if (
            existing[0] != manifest.channel_binding_id
            or existing[1] != config.snapshot
            or existing[2] != manifest.snapshot_digest
            or existing[3] not in {"draft", "approved", "published"}
            or existing[4] != manifest.actor_id
            or not _event_matches(connection, manifest, "candidate_staged")
        ):
            raise PublicKnowledgeReleaseError("the staged candidate conflicts")
        return True
    _active_route(connection, manifest)
    connection.execute(
        "INSERT INTO lucy.public_projection_candidates"
        "(id,channel_binding_id,snapshot,snapshot_digest,status,created_by,created_at) "
        "VALUES(%s,%s,%s::jsonb,%s,'draft',%s,now())",
        (
            manifest.candidate_id,
            manifest.channel_binding_id,
            json.dumps(config.snapshot, separators=(",", ":"), ensure_ascii=False),
            manifest.snapshot_digest,
            manifest.actor_id,
        ),
    )
    connection.execute(
        "INSERT INTO lucy.public_projection_events"
        "(id,channel_binding_id,event_type,candidate_id,version_id,actor_id,occurred_at) "
        "VALUES(%s,%s,'candidate_staged',%s,NULL,%s,now())",
        (
            manifest.transition_id,
            manifest.channel_binding_id,
            manifest.candidate_id,
            manifest.actor_id,
        ),
    )
    return False


def _approve(
    connection: psycopg.Connection[Any], config: PublicKnowledgeReleaseConfig
) -> bool:
    manifest = config.manifest
    _require_actor(connection, manifest, "approver")
    assert manifest.approval_id is not None
    existing = connection.execute(
        "SELECT candidate_id,approved_digest,approved_by FROM lucy.public_projection_approvals "
        "WHERE id=%s",
        (manifest.approval_id,),
    ).fetchone()
    if existing is not None:
        if existing != (manifest.candidate_id, manifest.snapshot_digest, manifest.actor_id) or not (
            _event_matches(connection, manifest, "candidate_approved")
        ):
            raise PublicKnowledgeReleaseError("the candidate approval conflicts")
        return True
    _active_route(connection, manifest)
    candidate = connection.execute(
        "SELECT snapshot,snapshot_digest,status,created_by "
        "FROM lucy.public_projection_candidates WHERE id=%s",
        (manifest.candidate_id,),
    ).fetchone()
    if candidate is None or candidate[:3] != (
        config.snapshot,
        manifest.snapshot_digest,
        "draft",
    ):
        raise PublicKnowledgeReleaseError("the candidate is not the reviewed draft")
    if candidate[3] == manifest.actor_id:
        raise PublicKnowledgeReleaseError("the publisher cannot approve its own candidate")
    connection.execute(
        "INSERT INTO lucy.public_projection_approvals"
        "(id,candidate_id,approved_digest,approved_by,approved_at) VALUES(%s,%s,%s,%s,now())",
        (
            manifest.approval_id,
            manifest.candidate_id,
            manifest.snapshot_digest,
            manifest.actor_id,
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
            manifest.transition_id,
            manifest.channel_binding_id,
            manifest.candidate_id,
            manifest.actor_id,
        ),
    )
    return False


def _require_eligible(snapshot: dict[str, Any], *, now: datetime) -> None:
    entries = snapshot.get("entries")
    if not isinstance(entries, list) or not entries:
        raise PublicKnowledgeReleaseError("the public knowledge snapshot is empty")
    for item in entries:
        try:
            effective_from = datetime.fromisoformat(item["effective_from"].replace("Z", "+00:00"))
            effective_until_raw = item.get("effective_until")
            effective_until = (
                None
                if effective_until_raw is None
                else datetime.fromisoformat(effective_until_raw.replace("Z", "+00:00"))
            )
        except (AttributeError, KeyError, TypeError, ValueError) as exc:
            raise PublicKnowledgeReleaseError("knowledge effective dates are invalid") from exc
        if effective_from > now or (effective_until is not None and effective_until <= now):
            raise PublicKnowledgeReleaseError("the snapshot contains ineligible knowledge")


def _activate(
    connection: psycopg.Connection[Any], config: PublicKnowledgeReleaseConfig
) -> bool:
    manifest = config.manifest
    _require_actor(connection, manifest, "publisher")
    assert manifest.approval_id is not None and manifest.version_id is not None
    active = connection.execute(
        "SELECT v.id,v.version,v.snapshot_digest FROM lucy.public_projection_routes r "
        "JOIN lucy.public_projection_versions v ON v.id=r.active_version_id "
        "WHERE r.channel_binding_id=%s",
        (manifest.channel_binding_id,),
    ).fetchone()
    activated = (
        manifest.version_id,
        manifest.expected_active_version + 1,
        manifest.snapshot_digest,
    )
    if active == activated:
        if not _event_matches(connection, manifest, "published"):
            raise PublicKnowledgeReleaseError("the activated version event conflicts")
        return True
    _active_route(connection, manifest)
    _require_eligible(config.snapshot, now=datetime.now(UTC))
    candidate = connection.execute(
        "SELECT c.snapshot,c.snapshot_digest,c.status,a.id,a.approved_digest "
        "FROM lucy.public_projection_candidates c "
        "JOIN lucy.public_projection_approvals a ON a.candidate_id=c.id "
        "WHERE c.id=%s",
        (manifest.candidate_id,),
    ).fetchone()
    if candidate != (
        config.snapshot,
        manifest.snapshot_digest,
        "approved",
        manifest.approval_id,
        manifest.snapshot_digest,
    ):
        raise PublicKnowledgeReleaseError("the exact approved candidate is unavailable")
    connection.execute(
        "INSERT INTO lucy.public_projection_versions"
        "(id,channel_binding_id,candidate_id,version,snapshot,snapshot_digest,published_at) "
        "VALUES(%s,%s,%s,%s,%s::jsonb,%s,now())",
        (
            manifest.version_id,
            manifest.channel_binding_id,
            manifest.candidate_id,
            manifest.expected_active_version + 1,
            json.dumps(config.snapshot, separators=(",", ":"), ensure_ascii=False),
            manifest.snapshot_digest,
        ),
    )
    updated = connection.execute(
        "UPDATE lucy.public_projection_routes SET active_version_id=%s,updated_at=now() "
        "WHERE channel_binding_id=%s AND active_version_id=%s",
        (
            manifest.version_id,
            manifest.channel_binding_id,
            manifest.expected_active_version_id,
        ),
    ).rowcount
    if updated != 1:
        raise PublicKnowledgeReleaseError("the active route changed during activation")
    connection.execute(
        "UPDATE lucy.public_projection_candidates SET status='published' WHERE id=%s",
        (manifest.candidate_id,),
    )
    connection.execute(
        "INSERT INTO lucy.public_projection_events"
        "(id,channel_binding_id,event_type,candidate_id,version_id,actor_id,occurred_at) "
        "VALUES(%s,%s,'published',%s,%s,%s,now())",
        (
            manifest.transition_id,
            manifest.channel_binding_id,
            manifest.candidate_id,
            manifest.version_id,
            manifest.actor_id,
        ),
    )
    return False


def run(config: PublicKnowledgeReleaseConfig) -> dict[str, object]:
    manifest = config.manifest
    with psycopg.connect(_conninfo(config.migration_url)) as connection:
        connection.execute("SET LOCAL lock_timeout = '15s'")
        connection.execute("SET LOCAL statement_timeout = '120s'")
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (MAINTENANCE_LOCK,))
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (ADMISSION_LOCK,))
        _verify_boundary(connection, manifest)
        operation = {"stage": _stage, "approve": _approve, "activate": _activate}[manifest.action]
        replayed = operation(connection, config)
    return {
        "contract": "lucy.utopia.public-knowledge-release-receipt.v1",
        "status": "passed",
        "action": manifest.action,
        "release_id": str(manifest.release_id),
        "schema_revision": manifest.schema_revision,
        "candidate_id": str(manifest.candidate_id),
        "snapshot_digest": manifest.snapshot_digest,
        "replayed": replayed,
    }


def main() -> int:
    try:
        report = run(PublicKnowledgeReleaseConfig.from_environment())
    except PublicKnowledgeReleaseError as exc:
        print(
            json.dumps(
                {
                    "contract": "lucy.utopia.public-knowledge-release-receipt.v1",
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
                    "contract": "lucy.utopia.public-knowledge-release-receipt.v1",
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
