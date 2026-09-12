"""Approved, immutable public snapshots with no private-memory fallback."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session, sessionmaker

from lucy.db.models import (
    ChannelBindingRow,
    NodeMembershipRow,
    PublicProjectionApprovalRow,
    PublicProjectionCandidateRow,
    PublicProjectionEventRow,
    PublicProjectionRouteRow,
    PublicProjectionVersionRow,
)
from lucy.public_contracts import PublicKnowledgeEntry, PublicKnowledgeSnapshot
from lucy.tenancy import ScopeNotFound


class PublicationRejected(ValueError):
    pass


@dataclass(frozen=True)
class PublicAnswer:
    answer: str
    source: str
    version: int
    snapshot_digest: str


@dataclass(frozen=True)
class PublicKnowledgeProjection:
    entries: tuple[PublicKnowledgeEntry, ...]
    version: int
    snapshot_digest: str


def canonical_snapshot(snapshot: dict[str, Any]) -> bytes:
    return json.dumps(snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def snapshot_digest(snapshot: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_snapshot(snapshot)).hexdigest()


def faq_snapshot(entries: list[dict[str, str]]) -> dict[str, Any]:
    if not entries:
        raise ValueError("a public snapshot needs at least one FAQ")
    normalized: list[dict[str, str]] = []
    seen: set[str] = set()
    for entry in entries:
        question = " ".join(entry["question"].split()).casefold()
        answer = entry["answer"].strip()
        source = entry["source"].strip()
        if not question or not answer or not source or question in seen:
            raise ValueError("FAQ entries must be unique and complete")
        seen.add(question)
        normalized.append({"question": question, "answer": answer, "source": source})
    normalized.sort(key=lambda item: item["question"])
    return {"schema": "lucy-public-faq-v1", "faqs": normalized}


def knowledge_snapshot(entries: list[dict[str, Any]]) -> dict[str, Any]:
    """Validate and canonicalize an R1 public-knowledge candidate."""

    validated = PublicKnowledgeSnapshot.model_validate(
        {"schema": "lucy-public-knowledge-v1", "entries": entries}
    )
    ids = [entry.id for entry in validated.entries]
    if len(ids) != len(set(ids)):
        raise ValueError("public knowledge entry ids must be unique")
    property_facts: dict[str, object] = {}
    for entry in validated.entries:
        if entry.property_slug is None:
            continue
        facts = entry.property_facts
        existing = property_facts.setdefault(entry.property_slug, facts)
        if existing != facts:
            raise ValueError("public knowledge property facts must be consistent per property")
    ordered = validated.model_copy(
        update={"entries": tuple(sorted(validated.entries, key=lambda entry: entry.id))}
    )
    return ordered.model_dump(mode="json", by_alias=True)


class PublicProjectionPublisher:
    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self._sessions = sessions

    def stage(
        self,
        *,
        channel_binding_id: UUID,
        entries: list[dict[str, str]],
        actor_id: UUID,
    ) -> tuple[UUID, str]:
        return self._stage_snapshot(
            channel_binding_id=channel_binding_id,
            snapshot=faq_snapshot(entries),
            actor_id=actor_id,
        )

    def stage_knowledge(
        self,
        *,
        channel_binding_id: UUID,
        entries: list[dict[str, Any]],
        actor_id: UUID,
    ) -> tuple[UUID, str]:
        """Stage validated R1 knowledge without making it active."""

        return self._stage_snapshot(
            channel_binding_id=channel_binding_id,
            snapshot=knowledge_snapshot(entries),
            actor_id=actor_id,
        )

    def _stage_snapshot(
        self,
        *,
        channel_binding_id: UUID,
        snapshot: dict[str, Any],
        actor_id: UUID,
    ) -> tuple[UUID, str]:
        digest = snapshot_digest(snapshot)
        candidate_id = uuid4()
        now = datetime.now(UTC)
        with self._sessions.begin() as session:
            self._require_actor(session, channel_binding_id, actor_id, {"owner", "publisher"})
            session.add(
                PublicProjectionCandidateRow(
                    id=candidate_id,
                    channel_binding_id=channel_binding_id,
                    snapshot=snapshot,
                    snapshot_digest=digest,
                    status="draft",
                    created_by=actor_id,
                    created_at=now,
                )
            )
            self._event(session, channel_binding_id, "candidate_staged", actor_id, candidate_id)
        return candidate_id, digest

    def approve(self, *, candidate_id: UUID, expected_digest: str, actor_id: UUID) -> UUID:
        approval_id = uuid4()
        with self._sessions.begin() as session:
            candidate = session.get(PublicProjectionCandidateRow, candidate_id)
            if candidate is None or candidate.snapshot_digest != expected_digest:
                raise PublicationRejected("candidate digest does not match reviewed snapshot")
            self._require_actor(
                session, candidate.channel_binding_id, actor_id, {"owner", "approver"}
            )
            if snapshot_digest(candidate.snapshot) != expected_digest:
                raise PublicationRejected("candidate content changed after staging")
            session.add(
                PublicProjectionApprovalRow(
                    id=approval_id,
                    candidate_id=candidate_id,
                    approved_digest=expected_digest,
                    approved_by=actor_id,
                    approved_at=datetime.now(UTC),
                )
            )
            candidate.status = "approved"
            self._event(
                session, candidate.channel_binding_id, "candidate_approved", actor_id, candidate_id
            )
        return approval_id

    def publish(self, *, candidate_id: UUID, actor_id: UUID) -> UUID:
        now = datetime.now(UTC)
        with self._sessions.begin() as session:
            candidate = session.get(PublicProjectionCandidateRow, candidate_id)
            approval = session.execute(
                select(PublicProjectionApprovalRow).where(
                    PublicProjectionApprovalRow.candidate_id == candidate_id
                )
            ).scalar_one_or_none()
            if candidate is None or approval is None:
                raise PublicationRejected("candidate has no approval")
            self._require_actor(
                session, candidate.channel_binding_id, actor_id, {"owner", "publisher"}
            )
            actual_digest = snapshot_digest(candidate.snapshot)
            if (
                actual_digest != candidate.snapshot_digest
                or actual_digest != approval.approved_digest
            ):
                raise PublicationRejected("approved bytes do not match candidate")
            next_version = (
                session.execute(
                    select(func.coalesce(func.max(PublicProjectionVersionRow.version), 0)).where(
                        PublicProjectionVersionRow.channel_binding_id
                        == candidate.channel_binding_id
                    )
                ).scalar_one()
                + 1
            )
            version_id = uuid4()
            session.add(
                PublicProjectionVersionRow(
                    id=version_id,
                    channel_binding_id=candidate.channel_binding_id,
                    candidate_id=candidate.id,
                    version=next_version,
                    snapshot=candidate.snapshot,
                    snapshot_digest=actual_digest,
                    published_at=now,
                )
            )
            route = session.get(PublicProjectionRouteRow, candidate.channel_binding_id)
            if route is None:
                route = PublicProjectionRouteRow(
                    channel_binding_id=candidate.channel_binding_id,
                    active_version_id=version_id,
                    updated_at=now,
                )
                session.add(route)
            else:
                route.active_version_id = version_id
                route.updated_at = now
            candidate.status = "published"
            self._event(
                session,
                candidate.channel_binding_id,
                "published",
                actor_id,
                candidate.id,
                version_id,
            )
        return version_id

    def withdraw(self, *, channel_binding_id: UUID, actor_id: UUID) -> None:
        """Reject the obsolete direct path; withdrawals require durable staging."""
        del channel_binding_id, actor_id
        raise PublicationRejected("publication withdrawal requires authority transition service")

    @staticmethod
    def _require_actor(
        session: Session,
        channel_id: UUID,
        actor_id: UUID,
        roles: set[str],
    ) -> None:
        permitted = session.execute(
            select(NodeMembershipRow.id)
            .join(
                ChannelBindingRow,
                ChannelBindingRow.workspace_id == NodeMembershipRow.workspace_id,
            )
            .where(
                ChannelBindingRow.id == channel_id,
                ChannelBindingRow.active.is_(True),
                NodeMembershipRow.principal_id == actor_id,
                NodeMembershipRow.status == "active",
                NodeMembershipRow.role.in_(roles),
            )
        ).scalar_one_or_none()
        if permitted is None:
            raise PublicationRejected("actor is not authorized for this public workspace")

    @staticmethod
    def _event(
        session: Session,
        channel_id: UUID,
        event_type: str,
        actor_id: UUID,
        candidate_id: UUID | None = None,
        version_id: UUID | None = None,
    ) -> None:
        session.add(
            PublicProjectionEventRow(
                id=uuid4(),
                channel_binding_id=channel_id,
                event_type=event_type,
                candidate_id=candidate_id,
                version_id=version_id,
                actor_id=actor_id,
                occurred_at=datetime.now(UTC),
            )
        )


class PublicProjectionReader:
    """Public data-plane reader. Its query surface contains projection tables only."""

    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self._sessions = sessions

    def answer(self, *, hostname: str, question: str) -> PublicAnswer:
        with self._sessions() as session:
            result = session.execute(
                text("SELECT lucy.public_projection_answer_v1(:hostname,:question)"),
                {"hostname": hostname, "question": question},
            ).scalar_one()
        if result is None:
            raise ScopeNotFound("public answer is unavailable")
        return PublicAnswer(
            answer=result["answer"],
            source=result["source"],
            version=result["version"],
            snapshot_digest=result["snapshot_digest"],
        )

    def answer_admitted(self, *, hostname: str, question: str, storage_epoch: UUID) -> PublicAnswer:
        """Read only through the epoch- and quarantine-gated public function."""

        with self._sessions() as session:
            result = session.execute(
                text("SELECT lucy.public_projection_answer_v2(:hostname,:question,:epoch)"),
                {"hostname": hostname, "question": question, "epoch": storage_epoch},
            ).scalar_one()
        if result is None:
            raise ScopeNotFound("public answer is unavailable")
        return PublicAnswer(
            answer=result["answer"],
            source=result["source"],
            version=result["version"],
            snapshot_digest=result["snapshot_digest"],
        )

    def knowledge_admitted(
        self, *, hostname: str, storage_epoch: UUID
    ) -> PublicKnowledgeProjection:
        """Read only currently effective records through the admitted public function."""

        with self._sessions() as session:
            result = session.execute(
                text("SELECT lucy.public_projection_knowledge_v1(:hostname,:epoch)"),
                {"hostname": hostname, "epoch": storage_epoch},
            ).scalar_one()
        if result is None:
            raise ScopeNotFound("public knowledge is unavailable")
        snapshot = PublicKnowledgeSnapshot.model_validate(
            {"schema": "lucy-public-knowledge-v1", "entries": result["entries"]}
        )
        return PublicKnowledgeProjection(
            entries=snapshot.entries,
            version=result["version"],
            snapshot_digest=result["snapshot_digest"],
        )
