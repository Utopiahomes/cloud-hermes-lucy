from __future__ import annotations

import os
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text, update
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError, IntegrityError

from lucy.db import create_session_factory
from lucy.db.models import (
    PublicProjectionCandidateRow,
    SecurityRealmRow,
    TenantAccountRow,
    WalletRegistrationRow,
)
from lucy.publication import (
    PublicationRejected,
    PublicProjectionPublisher,
    PublicProjectionReader,
)
from lucy.tenancy import ScopeNotFound, TenancyService

DATABASE_URL = os.getenv("LUCY_TEST_DATABASE_URL")
OWNER_DATABASE_URL = os.getenv("LUCY_TEST_OWNER_DATABASE_URL")
PUBLIC_DATABASE_URL = os.getenv("LUCY_TEST_PUBLIC_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="requires PostgreSQL integration database")


@pytest.fixture(autouse=True)
def clean_r1_tables() -> None:
    assert OWNER_DATABASE_URL is not None
    parsed = make_url(OWNER_DATABASE_URL)
    if (parsed.database, parsed.host, parsed.port) != ("lucy_test", "127.0.0.1", 54329):
        raise RuntimeError("refusing to clear a non-synthetic database")
    engine = create_engine(OWNER_DATABASE_URL)
    with engine.begin() as connection:
        connection.execute(
            text(
                "TRUNCATE lucy.public_projection_events, lucy.public_projection_routes, "
                "lucy.public_projection_versions, lucy.public_projection_approvals, "
                "lucy.public_projection_candidates, lucy.lucy_instances, "
                "lucy.node_memberships, lucy.channel_bindings, lucy.wallet_registrations, "
                "lucy.workspaces, lucy.realm_bindings, lucy.node_tenures, lucy.security_realms, "
                "lucy.nodes, lucy.tenant_accounts, lucy.principals CASCADE"
            )
        )
    engine.dispose()


def _foundation(service: TenancyService, slug: str, host: str):
    return service.create_node_foundation(
        account_slug=slug,
        account_name=slug.title(),
        node_slug=slug,
        node_name=slug.title(),
        node_kind="organization",
        realm_slug=f"{slug}-realm",
        workspace_slug="website",
        hostname=host,
    )


def test_synthetic_utopia_public_slice_is_scoped_immutable_and_withdrawable() -> None:
    assert DATABASE_URL is not None
    sessions = create_session_factory(DATABASE_URL)
    tenancy = TenancyService(sessions)
    publisher = PublicProjectionPublisher(sessions)
    assert PUBLIC_DATABASE_URL is not None
    public_sessions = create_session_factory(PUBLIC_DATABASE_URL)
    reader = PublicProjectionReader(public_sessions)
    actor = tenancy.create_principal(
        issuer="https://synthetic-idp.invalid", subject="ray", kind="human", display_name="Ray"
    )
    utopia = _foundation(tenancy, "utopia", "utopiahomes.test")
    alpha = _foundation(tenancy, "alpha", "alpha.test")
    tenancy.grant_workspace_membership(
        principal_id=actor, workspace_id=utopia.workspace_id, role="owner"
    )
    tenancy.grant_workspace_membership(
        principal_id=actor, workspace_id=alpha.workspace_id, role="owner"
    )
    outsider = tenancy.create_principal(
        issuer="https://synthetic-idp.invalid",
        subject="outsider",
        kind="human",
        display_name="Outsider",
    )
    with pytest.raises(PublicationRejected, match="not authorized"):
        publisher.stage(
            channel_binding_id=utopia.channel_binding_id,
            actor_id=outsider,
            entries=[{"question": "Forged?", "answer": "No", "source": "synthetic://forged"}],
        )

    utopia_candidate, digest = publisher.stage(
        channel_binding_id=utopia.channel_binding_id,
        actor_id=actor,
        entries=[
            {
                "question": "Where is Utopia Homes located?",
                "answer": "Bethany Beach, Delaware.",
                "source": "synthetic://utopia/location",
            }
        ],
    )
    with pytest.raises(PublicationRejected, match="digest"):
        publisher.approve(candidate_id=utopia_candidate, expected_digest="0" * 64, actor_id=actor)
    publisher.approve(candidate_id=utopia_candidate, expected_digest=digest, actor_id=actor)
    publisher.publish(candidate_id=utopia_candidate, actor_id=actor)

    alpha_candidate, alpha_digest = publisher.stage(
        channel_binding_id=alpha.channel_binding_id,
        actor_id=actor,
        entries=[
            {
                "question": "What is Alpha's private canary?",
                "answer": "ALPHA-PRIVATE-CANARY",
                "source": "synthetic://alpha/canary",
            }
        ],
    )
    publisher.approve(candidate_id=alpha_candidate, expected_digest=alpha_digest, actor_id=actor)
    alpha_version = publisher.publish(candidate_id=alpha_candidate, actor_id=actor)

    with (
        pytest.raises(IntegrityError, match="public_projection_routes"),
        sessions.begin() as session,
    ):
        session.execute(
            text(
                "UPDATE lucy.public_projection_routes SET active_version_id=:foreign "
                "WHERE channel_binding_id=:utopia"
            ),
            {"foreign": alpha_version, "utopia": utopia.channel_binding_id},
        )

    answer = reader.answer(
        hostname="UTOPIAHOMES.TEST.", question=" Where is  Utopia Homes located? "
    )
    assert answer.answer == "Bethany Beach, Delaware."
    assert answer.source == "synthetic://utopia/location"
    assert answer.version == 1

    with pytest.raises(ScopeNotFound, match="unavailable"):
        reader.answer(hostname="utopiahomes.test", question="What is Alpha's private canary?")
    with pytest.raises(ScopeNotFound, match="unavailable"):
        reader.answer(hostname="forged-utopia.test", question="Where is Utopia Homes located?")
    with pytest.raises(DBAPIError, match="permission denied"), public_sessions() as public_session:
        public_session.execute(text("SELECT * FROM lucy.public_projection_versions"))

    with (
        pytest.raises(DBAPIError, match="approved public projection bytes are immutable"),
        sessions.begin() as session,
    ):
        session.execute(
            update(PublicProjectionCandidateRow)
            .where(PublicProjectionCandidateRow.id == utopia_candidate)
            .values(snapshot={"schema": "lucy-public-faq-v1", "faqs": []})
        )
    # The database trigger, not just application code, rejects post-review byte changes.
    # SQLAlchemy wraps the trigger exception as DBAPIError.
    # The transaction above is intentionally expected to fail.
    with pytest.raises(PublicationRejected, match="authority transition service"):
        publisher.withdraw(channel_binding_id=utopia.channel_binding_id, actor_id=actor)


def test_database_enforces_one_wallet_per_node_and_immutable_tenure() -> None:
    assert DATABASE_URL is not None
    sessions = create_session_factory(DATABASE_URL)
    foundation = _foundation(TenancyService(sessions), "utopia", "utopiahomes.test")
    with pytest.raises(IntegrityError), sessions.begin() as session:
        session.add(
            WalletRegistrationRow(
                id=uuid4(),
                node_id=foundation.node_id,
                tenure_id=foundation.tenure_id,
                status="REGISTERED_NONSPENDABLE",
                created_at=datetime.now(UTC),
            )
        )
    assert OWNER_DATABASE_URL is not None
    owner_sessions = create_session_factory(OWNER_DATABASE_URL)
    with pytest.raises(DBAPIError, match="append-only"), owner_sessions.begin() as session:
        session.execute(
            text("UPDATE lucy.node_tenures SET sequence=2 WHERE id=:id"),
            {"id": foundation.tenure_id},
        )


def test_initial_topology_has_five_nodes_four_accounts_and_isolated_realms() -> None:
    assert DATABASE_URL is not None
    sessions = create_session_factory(DATABASE_URL)
    tenancy = TenancyService(sessions)
    specifications = (
        ("raymond", "Raymond", "raymond", "Raymond DeLuca", "person", "raymond.test"),
        ("utopia", "Utopia", "utopia", "Utopia Homes", "organization", "utopia.test"),
        ("platform", "Platform", "consulting", "SC Consulting", "organization", "sc.test"),
        ("platform", "Platform", "service", "Cloud Lucy Service", "service", "lucy.test"),
        ("alpha", "Alpha", "alpha", "Client Alpha", "organization", "alpha.test"),
    )
    foundations = [
        tenancy.create_node_foundation(
            account_slug=account_slug,
            account_name=account_name,
            node_slug=node_slug,
            node_name=node_name,
            node_kind=node_kind,
            realm_slug=f"{node_slug}-realm",
            workspace_slug="website",
            hostname=hostname,
        )
        for account_slug, account_name, node_slug, node_name, node_kind, hostname in specifications
    ]
    with sessions() as session:
        assert session.query(TenantAccountRow).count() == 4
        assert session.query(SecurityRealmRow).count() == 5
        assert session.query(WalletRegistrationRow).count() == 5
    assert len({item.realm_id for item in foundations}) == 5
    assert len({item.wallet_id for item in foundations}) == 5
