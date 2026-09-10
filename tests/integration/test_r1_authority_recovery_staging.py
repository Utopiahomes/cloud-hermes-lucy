from __future__ import annotations

import os
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError

from lucy.authority_recovery import AuthorityTransitionRequestV1, AuthorityTransitionService
from lucy.db import create_session_factory
from lucy.publication import PublicationRejected, PublicProjectionPublisher, PublicProjectionReader
from lucy.tenancy import ScopeNotFound, TenancyService

APP_URL = os.getenv("LUCY_TEST_DATABASE_URL")
OWNER_URL = os.getenv("LUCY_TEST_OWNER_DATABASE_URL")
TRANSITION_URL = os.getenv("LUCY_TEST_AUTHORITY_DATABASE_URL")
RECOVERY_URL = os.getenv("LUCY_TEST_AUTHORITY_RECOVERY_DATABASE_URL")
PUBLIC_URL = os.getenv("LUCY_TEST_PUBLIC_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not all((APP_URL, OWNER_URL, TRANSITION_URL, RECOVERY_URL, PUBLIC_URL)),
    reason="requires PostgreSQL authority-recovery integration database",
)


@pytest.fixture(autouse=True)
def clean_authority_tables() -> None:
    assert OWNER_URL is not None
    engine = create_engine(OWNER_URL)
    with engine.begin() as connection:
        if connection.scalar(text("SELECT current_database()")) != "lucy_test":
            raise RuntimeError("refusing to clear a non-synthetic database")
        connection.execute(
            text(
                "TRUNCATE lucy.authority_recovery_outbox_v1,"
                "lucy.authority_transition_events_v1,lucy.public_projection_events,"
                "lucy.public_projection_routes,lucy.public_projection_versions,"
                "lucy.public_projection_approvals,lucy.public_projection_candidates,"
                "lucy.lucy_instances,lucy.node_memberships,lucy.channel_bindings,"
                "lucy.wallet_registrations,lucy.workspaces,lucy.realm_bindings,"
                "lucy.node_tenures,lucy.security_realms,lucy.nodes,"
                "lucy.tenant_accounts,lucy.principals CASCADE"
            )
        )
    engine.dispose()


def _request(subject_id: UUID, actor_id: UUID, *, key: str) -> AuthorityTransitionRequestV1:
    return AuthorityTransitionRequestV1(
        subject_id=subject_id,
        actor_id=actor_id,
        stream_id=uuid4(),
        authority_epoch=1,
        idempotency_key=key,
        source_authority_ref="owner-interaction:synthetic",
        source_authority_digest="a" * 64,
    )


def _published_foundation():
    assert APP_URL is not None
    sessions = create_session_factory(APP_URL)
    tenancy = TenancyService(sessions)
    foundation = tenancy.create_node_foundation(
        account_slug="utopia",
        account_name="Utopia",
        node_slug="utopia",
        node_name="Utopia Homes",
        node_kind="organization",
        realm_slug="utopia-realm",
        workspace_slug="website",
        hostname="utopia.test",
    )
    owner = tenancy.create_principal(
        issuer="synthetic", subject="owner", kind="human", display_name="Owner"
    )
    publisher_actor = tenancy.create_principal(
        issuer="synthetic", subject="publisher", kind="human", display_name="Publisher"
    )
    owner_membership = tenancy.grant_workspace_membership(
        principal_id=owner, workspace_id=foundation.workspace_id, role="owner"
    )
    publisher_membership = tenancy.grant_workspace_membership(
        principal_id=publisher_actor, workspace_id=foundation.workspace_id, role="publisher"
    )
    publisher = PublicProjectionPublisher(sessions)
    candidate, digest = publisher.stage(
        channel_binding_id=foundation.channel_binding_id,
        entries=[{"question": "hello", "answer": "Hi", "source": "synthetic"}],
        actor_id=publisher_actor,
    )
    publisher.approve(candidate_id=candidate, expected_digest=digest, actor_id=owner)
    publisher.publish(candidate_id=candidate, expected_digest=digest, actor_id=publisher_actor)
    return foundation, owner, owner_membership, publisher_actor, publisher_membership, publisher


def test_restrictions_apply_locally_before_separate_durable_acknowledgement() -> None:
    assert TRANSITION_URL is not None and RECOVERY_URL is not None and PUBLIC_URL is not None
    foundation, owner, _, publisher_actor, publisher_membership, publisher = (
        _published_foundation()
    )
    transition = AuthorityTransitionService(create_session_factory(TRANSITION_URL))
    recovery = AuthorityTransitionService(create_session_factory(RECOVERY_URL))

    membership_request = _request(
        publisher_membership, owner, key="authority:membership:synthetic-1"
    )
    pending_membership = transition.revoke_membership(membership_request)
    assert pending_membership.state == "PERSISTENCE_PENDING"
    assert pending_membership.new_generation == pending_membership.previous_generation + 1
    with pytest.raises(PublicationRejected, match="not authorized"):
        publisher.stage(
            channel_binding_id=foundation.channel_binding_id,
            entries=[{"question": "new", "answer": "No", "source": "synthetic"}],
            actor_id=publisher_actor,
        )
    replay = transition.revoke_membership(membership_request)
    assert replay.replayed and replay.event_id == pending_membership.event_id
    with pytest.raises(DBAPIError, match="acknowledgement unavailable"):
        recovery.acknowledge(
            event_id=pending_membership.event_id,
            journal_sequence=1,
            journal_event_digest="d" * 64,
            journal_head_digest="d" * 64,
        )

    withdrawal = transition.withdraw_publication(
        _request(
            foundation.channel_binding_id,
            owner,
            key="authority:publication:synthetic-1",
        )
    )
    assert withdrawal.state == "PERSISTENCE_PENDING"
    with pytest.raises(ScopeNotFound):
        PublicProjectionReader(create_session_factory(PUBLIC_URL)).answer(
            hostname="utopia.test", question="hello"
        )

    prepared = transition.prepare(
        event_id=withdrawal.event_id,
        journal_sequence=2,
        journal_previous_digest="c" * 64,
        journal_event_digest="b" * 64,
    )
    assert prepared.journal_sequence == 2
    assert transition.prepare(
        event_id=withdrawal.event_id,
        journal_sequence=2,
        journal_previous_digest="c" * 64,
        journal_event_digest="b" * 64,
    ).journal_event_digest == "b" * 64
    with pytest.raises(DBAPIError, match="preparation conflicts"):
        transition.prepare(
            event_id=withdrawal.event_id,
            journal_sequence=2,
            journal_previous_digest="c" * 64,
            journal_event_digest="e" * 64,
        )
    exact = recovery.acknowledge(
        event_id=withdrawal.event_id,
        journal_sequence=2,
        journal_event_digest="b" * 64,
        journal_head_digest="b" * 64,
    )
    assert exact.state == "DURABLY_RECORDED"
    assert recovery.acknowledge(
        event_id=withdrawal.event_id,
        journal_sequence=2,
        journal_event_digest="b" * 64,
        journal_head_digest="b" * 64,
    ).replayed
    with pytest.raises(DBAPIError, match="conflicts"):
        recovery.acknowledge(
            event_id=withdrawal.event_id,
            journal_sequence=3,
            journal_event_digest="c" * 64,
            journal_head_digest="c" * 64,
        )


def test_roles_are_execute_only_and_cannot_cross_the_transition_boundary() -> None:
    assert APP_URL is not None and TRANSITION_URL is not None and RECOVERY_URL is not None
    foundation, owner, owner_membership, _, _, _ = _published_foundation()
    transition = AuthorityTransitionService(create_session_factory(TRANSITION_URL))
    recovery = AuthorityTransitionService(create_session_factory(RECOVERY_URL))
    request = _request(
        foundation.channel_binding_id, owner, key="authority:publication:synthetic-boundary"
    )

    with create_engine(APP_URL).begin() as connection, pytest.raises(
        DBAPIError, match="requires authority transition"
    ):
        connection.execute(
            text(
                "UPDATE lucy.public_projection_routes SET active_version_id=NULL "
                "WHERE channel_binding_id=:channel"
            ),
            {"channel": foundation.channel_binding_id},
        )
    for url in (TRANSITION_URL, RECOVERY_URL):
        with create_engine(url).begin() as connection, pytest.raises(
            DBAPIError, match="permission denied"
        ):
            connection.execute(text("SELECT * FROM lucy.authority_transition_events_v1"))
    with pytest.raises(DBAPIError, match="permission denied"):
        recovery.withdraw_publication(request)
    with pytest.raises(DBAPIError, match="permission denied"):
        transition.acknowledge(
            event_id=uuid4(),
            journal_sequence=1,
            journal_event_digest="b" * 64,
            journal_head_digest="b" * 64,
        )

    with pytest.raises(DBAPIError, match="last owner"):
        transition.revoke_membership(
            _request(owner_membership, owner, key="authority:last-owner:synthetic")
        )


def test_idempotency_and_workspace_authority_are_exact() -> None:
    assert APP_URL is not None and TRANSITION_URL is not None
    foundation, owner, _, _, publisher_membership, _ = _published_foundation()
    tenancy = TenancyService(create_session_factory(APP_URL))
    outsider = tenancy.create_principal(
        issuer="synthetic", subject="outsider", kind="human", display_name="Outsider"
    )
    transition = AuthorityTransitionService(create_session_factory(TRANSITION_URL))
    request = _request(publisher_membership, owner, key="authority:membership:exact")
    transition.revoke_membership(request)

    with pytest.raises(DBAPIError, match="idempotency conflict"):
        transition.revoke_membership(
            request.model_copy(update={"source_authority_digest": "f" * 64})
        )
    with pytest.raises(DBAPIError, match="unavailable"):
        transition.withdraw_publication(
            _request(
                foundation.channel_binding_id,
                outsider,
                key="authority:publication:outsider",
            )
        )
