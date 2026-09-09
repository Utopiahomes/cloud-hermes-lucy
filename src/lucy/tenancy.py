"""R1 tenant directory operations with server-resolved channel scope."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from lucy.db.models import (
    ChannelBindingRow,
    NodeMembershipRow,
    NodeRow,
    NodeTenureRow,
    PrincipalRow,
    RealmBindingRow,
    SecurityRealmRow,
    TenantAccountRow,
    WalletRegistrationRow,
    WorkspaceRow,
)


class ScopeNotFound(LookupError):
    """The trusted ingress binding does not resolve to an active scope."""


@dataclass(frozen=True)
class ResolvedChannelScope:
    channel_binding_id: UUID
    node_id: UUID
    tenure_id: UUID
    workspace_id: UUID


@dataclass(frozen=True)
class NodeFoundation:
    account_id: UUID
    node_id: UUID
    tenure_id: UUID
    realm_id: UUID
    workspace_id: UUID
    channel_binding_id: UUID
    wallet_id: UUID


def normalize_hostname(hostname: str) -> str:
    normalized = hostname.strip().rstrip(".").lower()
    if not normalized or len(normalized) > 253 or "/" in normalized or ":" in normalized:
        raise ValueError("invalid hostname")
    labels = normalized.split(".")
    if len(labels) < 2 or any(not label or len(label) > 63 for label in labels):
        raise ValueError("invalid hostname")
    return normalized


class TenancyService:
    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self._sessions = sessions

    def create_node_foundation(
        self,
        *,
        account_slug: str,
        account_name: str,
        node_slug: str,
        node_name: str,
        node_kind: str,
        realm_slug: str,
        workspace_slug: str,
        hostname: str,
    ) -> NodeFoundation:
        """Create one empty R1 node boundary; production seeding is deliberately separate."""
        now = datetime.now(UTC)
        account_id, node_id, tenure_id = uuid4(), uuid4(), uuid4()
        realm_id, workspace_id, channel_id, wallet_id = uuid4(), uuid4(), uuid4(), uuid4()
        host = normalize_hostname(hostname)
        with self._sessions.begin() as session:
            account = session.execute(
                select(TenantAccountRow).where(TenantAccountRow.slug == account_slug)
            ).scalar_one_or_none()
            if account is None:
                session.add(
                    TenantAccountRow(
                        id=account_id,
                        slug=account_slug,
                        display_name=account_name,
                        created_at=now,
                    )
                )
            else:
                if account.display_name != account_name:
                    raise ValueError("existing account label does not match")
                account_id = account.id
            session.add_all(
                [
                    NodeRow(
                        id=node_id,
                        slug=node_slug,
                        display_name=node_name,
                        node_kind=node_kind,
                        created_at=now,
                    ),
                    SecurityRealmRow(id=realm_id, slug=realm_slug, created_at=now),
                ]
            )
            session.flush()
            session.add(
                NodeTenureRow(
                    id=tenure_id,
                    node_id=node_id,
                    account_id=account_id,
                    sequence=1,
                    starts_at=now,
                    ends_at=None,
                )
            )
            session.flush()
            session.add_all(
                [
                    RealmBindingRow(
                        id=uuid4(),
                        tenure_id=tenure_id,
                        realm_id=realm_id,
                        binding_version=1,
                        valid_from=now,
                        valid_to=None,
                    ),
                    WorkspaceRow(
                        id=workspace_id,
                        node_id=node_id,
                        tenure_id=tenure_id,
                        slug=workspace_slug,
                        workspace_kind="public_projection",
                        created_at=now,
                    ),
                    WalletRegistrationRow(
                        id=wallet_id,
                        node_id=node_id,
                        tenure_id=tenure_id,
                        status="REGISTERED_NONSPENDABLE",
                        created_at=now,
                    ),
                ]
            )
            session.flush()
            session.add(
                ChannelBindingRow(
                    id=channel_id,
                    hostname=host,
                    node_id=node_id,
                    tenure_id=tenure_id,
                    workspace_id=workspace_id,
                    channel_kind="website_public",
                    active=True,
                    created_at=now,
                )
            )
        return NodeFoundation(
            account_id, node_id, tenure_id, realm_id, workspace_id, channel_id, wallet_id
        )

    def create_principal(self, *, issuer: str, subject: str, kind: str, display_name: str) -> UUID:
        principal_id = uuid4()
        with self._sessions.begin() as session:
            session.add(
                PrincipalRow(
                    id=principal_id,
                    issuer=issuer,
                    subject=subject,
                    principal_kind=kind,
                    display_name=display_name,
                    created_at=datetime.now(UTC),
                )
            )
        return principal_id

    def grant_workspace_membership(
        self, *, principal_id: UUID, workspace_id: UUID, role: str
    ) -> UUID:
        membership_id = uuid4()
        with self._sessions.begin() as session:
            session.add(
                NodeMembershipRow(
                    id=membership_id,
                    principal_id=principal_id,
                    workspace_id=workspace_id,
                    role=role,
                    status="active",
                    granted_at=datetime.now(UTC),
                )
            )
        return membership_id

    def resolve_public_hostname(self, hostname: str) -> ResolvedChannelScope:
        host = normalize_hostname(hostname)
        with self._sessions() as session:
            row = session.execute(
                select(ChannelBindingRow).where(
                    ChannelBindingRow.hostname == host,
                    ChannelBindingRow.channel_kind == "website_public",
                    ChannelBindingRow.active.is_(True),
                )
            ).scalar_one_or_none()
        if row is None:
            # One uniform result for unknown, foreign, inactive, or malformed caller scope.
            raise ScopeNotFound("public channel is unavailable")
        return ResolvedChannelScope(row.id, row.node_id, row.tenure_id, row.workspace_id)
