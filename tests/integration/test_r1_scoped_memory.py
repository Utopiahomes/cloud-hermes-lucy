from __future__ import annotations

import os
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError

from lucy.db import create_session_factory
from lucy.db.models import RealmBindingRow, RealmContentScopeRow, RealmServiceBindingRow
from lucy.scoped_memory import ScopedMemoryService, ScopedMemoryUnavailable, ScopedMemoryWrite
from lucy.tenancy import TenancyService

APP_URL = os.getenv("LUCY_TEST_DATABASE_URL")
OWNER_URL = os.getenv("LUCY_TEST_OWNER_DATABASE_URL")
RAYMOND_URL = os.getenv("LUCY_TEST_RAYMOND_DATABASE_URL")
UTOPIA_URL = os.getenv("LUCY_TEST_UTOPIA_DATABASE_URL")
ALPHA_URL = os.getenv("LUCY_TEST_ALPHA_DATABASE_URL")
pytestmark = pytest.mark.skipif(not APP_URL, reason="requires PostgreSQL integration database")


@pytest.fixture(autouse=True)
def clean_scoped_tables() -> None:
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
                "lucy.workspaces, lucy.realm_bindings, lucy.node_tenures, lucy.security_realms, "
                "lucy.nodes, lucy.tenant_accounts, lucy.principals CASCADE"
            )
        )
    engine.dispose()


def _provision(
    tenancy: TenancyService,
    *,
    slug: str,
    login: str,
    app_sessions,
    owner_sessions,
) -> None:
    foundation = tenancy.create_node_foundation(
        account_slug=slug,
        account_name=slug.title(),
        node_slug=slug,
        node_name=slug.title(),
        node_kind="organization",
        realm_slug=f"{slug}-realm",
        workspace_slug="private",
        hostname=f"{slug}.test",
        workspace_kind="private",
        channel_kind="internal",
    )
    principal_id = tenancy.create_principal(
        issuer="https://workload.invalid",
        subject=f"render:{slug}:routine",
        kind="service",
        display_name=f"{slug} routine",
    )
    with app_sessions() as session:
        realm_binding_id = session.execute(
            select(RealmBindingRow.id).where(
                RealmBindingRow.tenure_id == foundation.tenure_id,
                RealmBindingRow.realm_id == foundation.realm_id,
            )
        ).scalar_one()
    content_scope_id = uuid4()
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
                realm_binding_id=realm_binding_id,
                workspace_id=foundation.workspace_id,
                deployment_id=uuid4(),
                created_at=datetime.now(UTC),
            )
        )
        session.flush()
        session.add(
            RealmServiceBindingRow(
                id=uuid4(),
                session_login=login,
                service_principal_id=principal_id,
                content_scope_id=content_scope_id,
                service_role="realm_routine",
                allowed_actions=["memory.read", "memory.write"],
                binding_generation=1,
                node_authz_epoch=1,
                active=True,
                created_at=datetime.now(UTC),
            )
        )


def test_raymond_utopia_alpha_logins_are_fixed_to_their_private_memory() -> None:
    assert all((APP_URL, OWNER_URL, RAYMOND_URL, UTOPIA_URL, ALPHA_URL))
    app_sessions = create_session_factory(APP_URL)
    owner_sessions = create_session_factory(OWNER_URL)
    tenancy = TenancyService(app_sessions)
    logins = {
        "raymond": ("lucy_raymond_routine", RAYMOND_URL),
        "utopia": ("lucy_utopia_routine", UTOPIA_URL),
        "alpha": ("lucy_alpha_routine", ALPHA_URL),
    }
    for slug, (login, _url) in logins.items():
        _provision(
            tenancy,
            slug=slug,
            login=login,
            app_sessions=app_sessions,
            owner_sessions=owner_sessions,
        )
    with owner_sessions.begin() as session:
        session.execute(
            text(
                "GRANT EXECUTE ON FUNCTION "
                "lucy.write_scoped_memory_claim_v1(text,text,text,text,bigint), "
                "lucy.search_governed_scoped_memory_v1(text,integer) TO "
                "lucy_raymond_routine,lucy_utopia_routine,lucy_alpha_routine"
            )
        )

    services = {
        slug: ScopedMemoryService(create_session_factory(url))
        for slug, (_login, url) in logins.items()
    }
    for slug, service in services.items():
        result = service.write(
            ScopedMemoryWrite(
                idempotency_key=f"{slug}-canary",
                subject=slug,
                predicate="private_canary",
                object=f"{slug.upper()}-PRIVATE-CANARY",
                confidence_millionths=1_000_000,
            )
        )
        assert result.replayed is False
        assert (
            service.write(
                ScopedMemoryWrite(
                    idempotency_key=f"{slug}-canary",
                    subject=slug,
                    predicate="private_canary",
                    object=f"{slug.upper()}-PRIVATE-CANARY",
                    confidence_millionths=1_000_000,
                )
            ).replayed
            is True
        )

    assert services["utopia"].search("UTOPIA-PRIVATE-CANARY")[0].object == ("UTOPIA-PRIVATE-CANARY")
    assert services["utopia"].search("ALPHA-PRIVATE-CANARY") == ()
    assert services["alpha"].search("RAYMOND-PRIVATE-CANARY") == ()

    for table_name in (
        "realm_content_scopes_v1",
        "realm_service_bindings_v1",
        "scoped_memory_claims_v1",
        "scoped_memory_events_v1",
    ):
        with (
            pytest.raises(DBAPIError, match="permission denied"),
            create_session_factory(UTOPIA_URL)() as session,
        ):
            session.execute(text(f"SELECT * FROM lucy.{table_name}"))

    with (
        pytest.raises(DBAPIError, match="permission denied"),
        app_sessions() as session,
    ):
        session.execute(text("SELECT lucy.search_scoped_memory_v1('anything',10)"))


def test_unbound_login_and_idempotency_conflict_fail_without_data() -> None:
    assert all((APP_URL, OWNER_URL, UTOPIA_URL, RAYMOND_URL))
    app_sessions = create_session_factory(APP_URL)
    owner_sessions = create_session_factory(OWNER_URL)
    tenancy = TenancyService(app_sessions)
    _provision(
        tenancy,
        slug="utopia",
        login="lucy_utopia_routine",
        app_sessions=app_sessions,
        owner_sessions=owner_sessions,
    )
    with owner_sessions.begin() as session:
        session.execute(
            text(
                "GRANT EXECUTE ON FUNCTION "
                "lucy.write_scoped_memory_claim_v1(text,text,text,text,bigint), "
                "lucy.search_scoped_memory_v1(text,integer) TO "
                "lucy_utopia_routine,lucy_raymond_routine"
            )
        )
    utopia = ScopedMemoryService(create_session_factory(UTOPIA_URL))
    original = ScopedMemoryWrite(
        idempotency_key="same-key",
        subject="Utopia",
        predicate="location",
        object="Delaware",
        confidence_millionths=900_000,
    )
    utopia.write(original)
    with pytest.raises(ScopedMemoryUnavailable, match="unavailable"):
        utopia.write(original.model_copy(update={"object": "Maryland"}))
    with pytest.raises(ScopedMemoryUnavailable, match="unavailable"):
        ScopedMemoryService(create_session_factory(RAYMOND_URL)).search("anything")
