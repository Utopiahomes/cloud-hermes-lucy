from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from pydantic import SecretStr
from sqlalchemy import create_engine, select, text, update
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError

from lucy.authenticated_memory import AuthenticatedScopedMemoryGateway
from lucy.contracts.security_v1_3 import (
    AuthenticationStrength,
    ExactObjectSelectorV1,
    OriginScopeV1,
    PrincipalType,
)
from lucy.db import create_session_factory
from lucy.db.models import (
    ChannelBindingRow,
    NodeMembershipRow,
    NodeRow,
    RealmBindingRow,
    RealmContentScopeRow,
    RealmServiceBindingRow,
)
from lucy.internal_admission import (
    InternalAdmissionDenied,
    PostgresDirectoryAdmissionAuthorizer,
    RealmInternalAdmissionService,
    VerifiedCustomerIdentityV1,
)
from lucy.realm_sessions import RealmRuntimeBindingV1, RealmSessionRegistry
from lucy.scoped_memory import ScopedMemoryWrite
from lucy.tenancy import NodeFoundation, TenancyService

APP_URL = os.getenv("LUCY_TEST_DATABASE_URL")
OWNER_URL = os.getenv("LUCY_TEST_OWNER_DATABASE_URL")
DIRECTORY_URL = os.getenv("LUCY_TEST_DIRECTORY_DATABASE_URL")
UTOPIA_URL = os.getenv("LUCY_TEST_UTOPIA_DATABASE_URL")
RAYMOND_URL = os.getenv("LUCY_TEST_RAYMOND_DATABASE_URL")
pytestmark = pytest.mark.skipif(not APP_URL, reason="requires PostgreSQL integration database")


@pytest.fixture(autouse=True)
def clean_directory_tables() -> None:
    assert OWNER_URL is not None
    parsed = make_url(OWNER_URL)
    if (parsed.database, parsed.host, parsed.port) != ("lucy_test", "127.0.0.1", 54329):
        raise RuntimeError("refusing to clear a non-synthetic database")
    engine = create_engine(OWNER_URL)
    with engine.begin() as connection:
        connection.execute(
            text(
                "TRUNCATE lucy.scoped_memory_events_v1, lucy.scoped_memory_claims_v1, "
                "lucy.realm_service_bindings_v1, lucy.realm_content_scopes_v1, "
                "lucy.public_projection_events, lucy.public_projection_routes, "
                "lucy.public_projection_versions, lucy.public_projection_approvals, "
                "lucy.public_projection_candidates, lucy.lucy_instances, "
                "lucy.node_memberships, lucy.channel_bindings, lucy.wallet_registrations, "
                "lucy.workspaces, lucy.realm_bindings, lucy.node_tenures, "
                "lucy.security_realms, lucy.nodes, lucy.tenant_accounts, "
                "lucy.principals CASCADE"
            )
        )
    engine.dispose()


class AudienceVerifier:
    def __init__(self, *, token: str, audience: str) -> None:
        self._token = token
        self._audience = audience

    def verify(
        self,
        credential: SecretStr,
        *,
        expected_issuer: str,
        expected_audience: str,
        checked_at: datetime,
    ) -> VerifiedCustomerIdentityV1:
        if (
            credential.get_secret_value() != self._token
            or expected_issuer != "https://identity.test"
            or expected_audience != self._audience
        ):
            raise PermissionError("synthetic identity rejected")
        return VerifiedCustomerIdentityV1(
            issuer=expected_issuer,
            subject="ray-subject",
            audience=expected_audience,
            principal_type=PrincipalType.HUMAN,
            authentication_strength=AuthenticationStrength.MFA,
            auth_time=checked_at - timedelta(minutes=1),
            expires_at=checked_at + timedelta(minutes=10),
            session_id=uuid4(),
        )


@dataclass(frozen=True)
class RealmFixture:
    foundation: NodeFoundation
    membership_id: UUID
    runtime_binding: RealmRuntimeBindingV1


def _provision_realm(
    tenancy: TenancyService,
    *,
    slug: str,
    runtime_login: str,
    runtime_url: str,
    human_principal_id: UUID,
    app_sessions,
    owner_sessions,
) -> RealmFixture:
    foundation = tenancy.create_node_foundation(
        account_slug=slug,
        account_name=slug.title(),
        node_slug=slug,
        node_name=slug.title(),
        node_kind="organization",
        realm_slug=f"{slug}-realm",
        workspace_slug="operations",
        hostname=f"internal.{slug}.test",
        workspace_kind="private",
        channel_kind="internal",
    )
    membership_id = tenancy.grant_workspace_membership(
        principal_id=human_principal_id,
        workspace_id=foundation.workspace_id,
        role="owner",
    )
    service_principal_id = tenancy.create_principal(
        issuer="https://workload.test",
        subject=f"render:{slug}:routine",
        kind="service",
        display_name=f"{slug.title()} routine",
    )
    with app_sessions() as session:
        realm_binding = session.execute(
            select(RealmBindingRow).where(
                RealmBindingRow.tenure_id == foundation.tenure_id,
                RealmBindingRow.realm_id == foundation.realm_id,
            )
        ).scalar_one()
    content_scope_id = uuid4()
    service_binding_id = uuid4()
    deployment_id = uuid4()
    with owner_sessions.begin() as session:
        session.add(
            RealmContentScopeRow(
                id=content_scope_id,
                tenant_account_id=foundation.account_id,
                node_id=foundation.node_id,
                node_tenure_id=foundation.tenure_id,
                tenure_epoch=1,
                security_realm_id=foundation.realm_id,
                storage_epoch=1,
                realm_binding_id=realm_binding.id,
                workspace_id=foundation.workspace_id,
                deployment_id=deployment_id,
                created_at=datetime.now(UTC),
            )
        )
        session.flush()
        session.add(
            RealmServiceBindingRow(
                id=service_binding_id,
                session_login=runtime_login,
                service_principal_id=service_principal_id,
                content_scope_id=content_scope_id,
                service_role="realm_routine",
                allowed_actions=["memory.read", "memory.write"],
                binding_generation=1,
                node_authz_epoch=1,
                policy_version=1,
                active=True,
                created_at=datetime.now(UTC),
            )
        )
    return RealmFixture(
        foundation=foundation,
        membership_id=membership_id,
        runtime_binding=RealmRuntimeBindingV1(
            workload_subject=f"render:{slug}:routine",
            service_principal_id=service_principal_id,
            service_binding_id=service_binding_id,
            target_scope=OriginScopeV1(
                tenant_account_id=foundation.account_id,
                node_id=foundation.node_id,
                node_tenure_id=foundation.tenure_id,
                tenure_epoch=1,
                security_realm_id=foundation.realm_id,
                storage_epoch=1,
            ),
            workspace_id=foundation.workspace_id,
            deployment_id=deployment_id,
            channel_binding_id=foundation.channel_binding_id,
            identity_issuer="https://identity.test",
            identity_audience=f"lucy:{slug}:internal",
            context_issuer=f"lucy:{slug}:admission",
            database_url=runtime_url,
            allowed_actions=frozenset({"memory.read", "memory.write"}),
            allowed_authentication_strengths=frozenset({AuthenticationStrength.MFA}),
            binding_generation=1,
            policy_version=1,
        ),
    )


@pytest.fixture
def realms() -> tuple[RealmFixture, RealmFixture, object, object]:
    assert all((APP_URL, OWNER_URL, DIRECTORY_URL, UTOPIA_URL, RAYMOND_URL))
    app_sessions = create_session_factory(APP_URL)
    owner_sessions = create_session_factory(OWNER_URL)
    tenancy = TenancyService(app_sessions)
    human_id = tenancy.create_principal(
        issuer="https://identity.test",
        subject="ray-subject",
        kind="human",
        display_name="Ray",
    )
    utopia = _provision_realm(
        tenancy,
        slug="utopia",
        runtime_login="lucy_utopia_routine",
        runtime_url=UTOPIA_URL,
        human_principal_id=human_id,
        app_sessions=app_sessions,
        owner_sessions=owner_sessions,
    )
    raymond = _provision_realm(
        tenancy,
        slug="raymond",
        runtime_login="lucy_raymond_routine",
        runtime_url=RAYMOND_URL,
        human_principal_id=human_id,
        app_sessions=app_sessions,
        owner_sessions=owner_sessions,
    )
    return utopia, raymond, app_sessions, owner_sessions


def _admission(binding: RealmRuntimeBindingV1, token: str) -> RealmInternalAdmissionService:
    assert DIRECTORY_URL is not None
    return RealmInternalAdmissionService(
        sessions=RealmSessionRegistry((binding,)),
        verified_workload_subject=binding.workload_subject,
        identity_verifier=AudienceVerifier(token=token, audience=binding.identity_audience),
        directory=PostgresDirectoryAdmissionAuthorizer(
            create_session_factory(DIRECTORY_URL)
        ),
    )


def _memory_gateway(
    fixture: RealmFixture, token: str
) -> AuthenticatedScopedMemoryGateway:
    return AuthenticatedScopedMemoryGateway(
        admission=_admission(fixture.runtime_binding, token),
        workspace_id=fixture.foundation.workspace_id,
    )


def _admit(service: RealmInternalAdmissionService, workspace_id: UUID, token: str):
    return service.admit(
        credential=SecretStr(token),
        request_id=uuid4(),
        action="memory.read",
        resource_selector=ExactObjectSelectorV1(object_id=workspace_id, object_version=1),
        checked_at=datetime.now(UTC),
    )


def test_utopia_and_raymond_resolve_separate_contexts_and_foreign_binding_fails(
    realms: tuple[RealmFixture, RealmFixture, object, object],
) -> None:
    utopia, raymond, _app_sessions, _owner_sessions = realms
    utopia_context = _admit(
        _admission(utopia.runtime_binding, "utopia-token"),
        utopia.foundation.workspace_id,
        "utopia-token",
    )
    raymond_context = _admit(
        _admission(raymond.runtime_binding, "raymond-token"),
        raymond.foundation.workspace_id,
        "raymond-token",
    )
    assert utopia_context.target_scope.security_realm_id == utopia.foundation.realm_id
    assert raymond_context.target_scope.security_realm_id == raymond.foundation.realm_id
    assert utopia_context.target_scope != raymond_context.target_scope

    forged = utopia.runtime_binding.model_copy(
        update={"channel_binding_id": raymond.foundation.channel_binding_id}
    )
    with pytest.raises(InternalAdmissionDenied, match="not authorized"):
        _admit(
            _admission(forged, "utopia-token"),
            utopia.foundation.workspace_id,
            "utopia-token",
        )

    stale_binding = utopia.runtime_binding.model_copy(update={"binding_generation": 2})
    with pytest.raises(InternalAdmissionDenied, match="not authorized"):
        _admit(
            _admission(stale_binding, "utopia-token"),
            utopia.foundation.workspace_id,
            "utopia-token",
        )


def test_authenticated_gateway_rechecks_authority_before_each_memory_effect(
    realms: tuple[RealmFixture, RealmFixture, object, object],
) -> None:
    utopia, raymond, app_sessions, owner_sessions = realms
    with owner_sessions.begin() as session:
        session.execute(
            text(
                "GRANT EXECUTE ON FUNCTION "
                "lucy.write_scoped_memory_claim_v1(text,text,text,text,bigint), "
                "lucy.search_scoped_memory_v1(text,integer) TO "
                "lucy_utopia_routine,lucy_raymond_routine"
            )
        )
    utopia_gateway = _memory_gateway(utopia, "utopia-token")
    raymond_gateway = _memory_gateway(raymond, "raymond-token")
    candidate = ScopedMemoryWrite(
        idempotency_key="authenticated-canary",
        subject="Lucy",
        predicate="realm",
        object="UTOPIA-AUTHENTICATED-CANARY",
        confidence_millionths=1_000_000,
    )

    assert utopia_gateway.write(
        credential=SecretStr("utopia-token"),
        request_id=uuid4(),
        candidate=candidate,
        checked_at=datetime.now(UTC),
    ).replayed is False
    assert utopia_gateway.search(
        credential=SecretStr("utopia-token"),
        request_id=uuid4(),
        query="UTOPIA-AUTHENTICATED-CANARY",
        checked_at=datetime.now(UTC),
    )[0].object == "UTOPIA-AUTHENTICATED-CANARY"
    assert raymond_gateway.search(
        credential=SecretStr("raymond-token"),
        request_id=uuid4(),
        query="UTOPIA-AUTHENTICATED-CANARY",
        checked_at=datetime.now(UTC),
    ) == ()

    with owner_sessions.begin() as session:
        session.execute(
            update(NodeMembershipRow)
            .where(NodeMembershipRow.id == utopia.membership_id)
            .values(status="revoked", generation=2)
        )
    with pytest.raises(InternalAdmissionDenied, match="not authorized"):
        utopia_gateway.search(
            credential=SecretStr("utopia-token"),
            request_id=uuid4(),
            query="UTOPIA-AUTHENTICATED-CANARY",
            checked_at=datetime.now(UTC),
        )


def test_revoked_membership_blocks_and_cannot_be_reactivated(
    realms: tuple[RealmFixture, RealmFixture, object, object],
) -> None:
    utopia, _raymond, app_sessions, owner_sessions = realms
    service = _admission(utopia.runtime_binding, "utopia-token")
    with owner_sessions.begin() as session:
        session.execute(
            update(NodeMembershipRow)
            .where(NodeMembershipRow.id == utopia.membership_id)
            .values(status="revoked", generation=2)
        )
    with pytest.raises(InternalAdmissionDenied, match="not authorized"):
        _admit(service, utopia.foundation.workspace_id, "utopia-token")

    with pytest.raises(DBAPIError, match="transition unavailable"), app_sessions.begin() as session:
        session.execute(
            update(NodeMembershipRow)
            .where(NodeMembershipRow.id == utopia.membership_id)
            .values(status="active", generation=3)
        )


def test_inactive_channel_blocks_and_cannot_be_reactivated(
    realms: tuple[RealmFixture, RealmFixture, object, object],
) -> None:
    utopia, _raymond, app_sessions, _owner_sessions = realms
    service = _admission(utopia.runtime_binding, "utopia-token")
    with app_sessions.begin() as session:
        session.execute(
            update(ChannelBindingRow)
            .where(ChannelBindingRow.id == utopia.foundation.channel_binding_id)
            .values(active=False, generation=2)
        )
    with pytest.raises(InternalAdmissionDenied, match="not authorized"):
        _admit(service, utopia.foundation.workspace_id, "utopia-token")

    with pytest.raises(DBAPIError, match="transition unavailable"), app_sessions.begin() as session:
        session.execute(
            update(ChannelBindingRow)
            .where(ChannelBindingRow.id == utopia.foundation.channel_binding_id)
            .values(active=True, generation=3)
        )


def test_disabled_service_binding_blocks_and_cannot_be_reactivated(
    realms: tuple[RealmFixture, RealmFixture, object, object],
) -> None:
    utopia, _raymond, _app_sessions, owner_sessions = realms
    service = _admission(utopia.runtime_binding, "utopia-token")
    with owner_sessions.begin() as session:
        session.execute(
            update(RealmServiceBindingRow)
            .where(RealmServiceBindingRow.id == utopia.runtime_binding.service_binding_id)
            .values(active=False, binding_generation=2)
        )
    with pytest.raises(InternalAdmissionDenied, match="not authorized"):
        _admit(service, utopia.foundation.workspace_id, "utopia-token")

    with pytest.raises(DBAPIError, match="mutation unavailable"), owner_sessions.begin() as session:
        session.execute(
            update(RealmServiceBindingRow)
            .where(RealmServiceBindingRow.id == utopia.runtime_binding.service_binding_id)
            .values(active=True, binding_generation=3)
        )


def test_node_authority_epoch_invalidates_stale_service_binding(
    realms: tuple[RealmFixture, RealmFixture, object, object],
) -> None:
    utopia, _raymond, app_sessions, _owner_sessions = realms
    service = _admission(utopia.runtime_binding, "utopia-token")
    with app_sessions.begin() as session:
        session.execute(
            update(NodeRow)
            .where(NodeRow.id == utopia.foundation.node_id)
            .values(authz_epoch=2)
        )
    with pytest.raises(InternalAdmissionDenied, match="not authorized"):
        _admit(service, utopia.foundation.workspace_id, "utopia-token")

    with pytest.raises(DBAPIError, match="transition unavailable"), app_sessions.begin() as session:
        session.execute(
            update(NodeRow)
            .where(NodeRow.id == utopia.foundation.node_id)
            .values(authz_epoch=1)
        )


def test_directory_login_cannot_read_tables_or_invoke_scoped_memory(
    realms: tuple[RealmFixture, RealmFixture, object, object],
) -> None:
    utopia, _raymond, _app_sessions, owner_sessions = realms
    assert DIRECTORY_URL is not None
    directory_sessions = create_session_factory(DIRECTORY_URL)
    for table_name in (
        "principals",
        "node_memberships",
        "realm_content_scopes_v1",
        "realm_service_bindings_v1",
        "scoped_memory_claims_v1",
    ):
        with pytest.raises(DBAPIError, match="permission denied"), directory_sessions() as session:
            session.execute(text(f"SELECT * FROM lucy.{table_name}"))
    with pytest.raises(DBAPIError, match="permission denied"), directory_sessions() as session:
        session.execute(text("SELECT lucy.search_scoped_memory_v1('anything',10)"))
    with owner_sessions() as session:
        memberships = session.execute(
            text(
                "SELECT parent.rolname FROM pg_auth_members am "
                "JOIN pg_roles child ON child.oid=am.member "
                "JOIN pg_roles parent ON parent.oid=am.roleid "
                "WHERE child.rolname='lucy_directory_admission'"
            )
        ).all()
    assert memberships == []
    assert utopia.runtime_binding.database_url.get_secret_value() not in repr(
        PostgresDirectoryAdmissionAuthorizer(directory_sessions)
    )
